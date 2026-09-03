package org.osservatorionessuno.libmvt.common;

import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import org.ahocorasick.trie.Emit;
import org.ahocorasick.trie.Trie;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Loads indicators from .json and .stix2 (JSON) files and matches strings.
 * Files are parsed as a stream (Gson's pull parser), never held in memory.
 * Exact-match types (process names, app IDs, hashes, …) are looked up in a map.
 * Domain/URL/path/name types use Aho-Corasick with whole-word matching.
 */
public class Indicators {
    public enum IndicatorType {
        OTHER,
        DOMAIN,
        URL,
        PROCESS,
        EMAIL,
        APP_ID,
        PROPERTY,
        FILE_PATH,
        FILE_NAME,
        FILE_HASH_MD5,
        FILE_HASH_SHA1,
        FILE_HASH_SHA256,
        APP_CERT_HASH_MD5,
        APP_CERT_HASH_SHA1,
        APP_CERT_HASH_SHA256,
        IOS_PROFILE_ID,
    }

    private static final Map<String, IndicatorType> TYPE_BY_KEY = new HashMap<>();

    static {
        register(IndicatorType.DOMAIN, "domain-name:value", "ipv4-addr:value");
        register(IndicatorType.URL, "url:value");
        register(IndicatorType.PROCESS, "process:name");
        register(IndicatorType.EMAIL, "email-addr:value");
        register(IndicatorType.APP_ID, "app:id");
        register(IndicatorType.PROPERTY, "android-property:name");
        register(IndicatorType.FILE_PATH, "file:path");
        register(IndicatorType.FILE_NAME, "file:name");
        register(IndicatorType.FILE_HASH_MD5, "file:hashes.md5");
        register(IndicatorType.FILE_HASH_SHA1, "file:hashes.sha1");
        register(IndicatorType.FILE_HASH_SHA256, "file:hashes.sha256");
        register(IndicatorType.APP_CERT_HASH_MD5, "app:cert.md5");
        register(IndicatorType.APP_CERT_HASH_SHA1, "app:cert.sha1");
        register(IndicatorType.APP_CERT_HASH_SHA256, "app:cert.sha256");
        register(IndicatorType.IOS_PROFILE_ID, "configuration-profile:id");
    }

    private static void register(IndicatorType type, String... keys) {
        for (String key : keys) {
            TYPE_BY_KEY.put(key, type);
        }
    }

    /** Types scanned with Aho-Corasick {@code ignoreCase().onlyWholeWords()}. Others are exact-match. */
    private static final Set<IndicatorType> SUBSTRING_MATCH_TYPES = EnumSet.of(
            IndicatorType.DOMAIN,
            IndicatorType.URL,
            IndicatorType.FILE_PATH,
            IndicatorType.FILE_NAME
    );

    /**
     * Linux {@code TASK_COMM_LEN} is 16 including the NUL, so dumps typically
     * show 15 characters. Some tools keep 16. Match a longer IOC by prefix
     * only when the observed name is exactly that truncated length.
     */
    private static final int PROCESS_COMM_TRUNCATED_MIN = 15;
    private static final int PROCESS_COMM_TRUNCATED_MAX = 16;

    /**
     * Single STIX 2 equality observation, compact or spaced:
     * {@code [url:value='https://example.com/track?id=1']} or
     * {@code [file:hashes.'SHA-256' = '...']}.
     * The key stops at {@code =} (so query strings stay in the value).
     * The value is a single-quoted literal; {@code \\.} is an escape pair so
     * {@code \'} cannot terminate it.
     */
    private static final Pattern STIX_EQUALITY_PATTERN = Pattern.compile(
            "^\\[\\s*(?<key>[^=\\s]+)\\s*=\\s*'(?<value>(?:\\\\.|[^'])*)'\\s*\\]$");
    private static final Pattern STIX_STRING_ESCAPE = Pattern.compile("\\\\(['\\\\])");

    /**
     * Map a STIX pattern key (e.g. {@code domain-name:value}) to its indicator type, or null.
     * Hash keys are normalised so spec-quoted forms match the lowercase MVT spelling.
     */
    public static IndicatorType typeForKey(String key) {
        if (key == null) return null;
        return TYPE_BY_KEY.get(normalizeIndicatorKey(key));
    }

    /**
     * STIX 2 requires single quotes around hash dictionary keys that contain hyphens
     * (e.g. {@code file:hashes.'SHA-256'}). MVT historically used the unquoted
     * lowercase form {@code file:hashes.sha256}. Strip quotes and hyphens from the
     * algorithm portion so all of these resolve to the same type:
     * {@code file:hashes.'SHA-256'}, {@code file:hashes.SHA-256},
     * {@code file:hashes.SHA256}, {@code file:hashes.sha256}.
     * The same applies to SHA-1/MD5 and {@code app:cert.*} keys.
     */
    static String normalizeIndicatorKey(String key) {
        String lower = key.trim().toLowerCase(Locale.ROOT);
        String prefix = lower.startsWith("file:hashes.") ? "file:hashes."
                : lower.startsWith("app:cert.") ? "app:cert."
                : null;
        if (prefix == null) return lower;
        return prefix + lower.substring(prefix.length())
                .replace("'", "")
                .replace("\"", "")
                .replace("-", "")
                .trim();
    }

    private final Map<IndicatorType, Trie.TrieBuilder> trieBuilders;
    private final Map<IndicatorType, Trie> tries;
    private final Map<IndicatorType, Map<String, LinkedHashSet<String>>> malwareByKeyword;
    private StringResolver stringResolver = new JvmMapStringResolver();

    public Indicators() {
        this.trieBuilders = new EnumMap<>(IndicatorType.class);
        this.tries = new EnumMap<>(IndicatorType.class);
        this.malwareByKeyword = new EnumMap<>(IndicatorType.class);

        for (IndicatorType type : EnumSet.copyOf(TYPE_BY_KEY.values())) {
            malwareByKeyword.put(type, new HashMap<>());
        }
        for (IndicatorType type : SUBSTRING_MATCH_TYPES) {
            trieBuilders.put(type, Trie.builder().ignoreCase().onlyWholeWords());
        }
    }

    /**
     * Set the resolver used to obtain human-readable strings.
     * On Android, pass {@code StringResolver.forAndroid(context)}.
     * On JVM, you may pass {@code StringResolver.forJvmDefault()} or a custom instance.
     */
    public void setStringResolver(StringResolver resolver) {
        if (resolver != null) {
            this.stringResolver = resolver;
        }
    }

    /** Load indicators from a folder containing .json or .stix2 files. */
    public void loadFromDirectory(File dir) {
        File[] files = (dir != null) ? dir.listFiles((d, name) -> name.endsWith(".json") || name.endsWith(".stix2")) : null;
        if (files == null) {
            throw new IllegalArgumentException("IOC directory is null or does not exist");
        }

        for (File f : files) {
            loadFile(f);
        }
        buildTries();
    }

    /**
     * Streaming parse: only the handful of fields in use are ever materialized, so a file is
     * never held in memory regardless of size or formatting (a DOM parse peaks at ~10x the
     * file size, which for a multi-megabyte feed is a per-scan OOM risk on a phone).
     * Accepts the same shapes as before: a STIX 2.x bundle-like object with an "objects"
     * array, an MVT-style object with an "indicators" array, or a bare top-level array
     * treated as a list of STIX objects. Unreadable or malformed files are skipped.
     */
    private void loadFile(File f) {
        try (JsonReader reader = new JsonReader(
                new InputStreamReader(new BufferedInputStream(new FileInputStream(f)), StandardCharsets.UTF_8))) {
            if (reader.peek() == JsonToken.BEGIN_ARRAY) {
                readStixObjects(reader);
                return;
            }
            reader.beginObject();
            while (reader.hasNext()) {
                String name = reader.nextName();
                if ("objects".equals(name) && reader.peek() == JsonToken.BEGIN_ARRAY) {
                    // STIX 2.x bundle-like: { "objects": [ { "type":"indicator", "pattern":"[...]"} ] }
                    readStixObjects(reader);
                } else if ("indicators".equals(name) && reader.peek() == JsonToken.BEGIN_ARRAY) {
                    // MVT-style: { "indicators": [ { "domain-name:value": ["a.com", ...], ... } ] }
                    readMvtCollections(reader);
                } else {
                    reader.skipValue();
                }
            }
            reader.endObject();
        } catch (Exception e) {
            // skip unreadable or malformed files, as before
        }
    }

    private void readStixObjects(JsonReader reader) throws IOException {
        StixFileState state = new StixFileState();
        reader.beginArray();
        while (reader.hasNext()) {
            if (reader.peek() != JsonToken.BEGIN_OBJECT) {
                reader.skipValue();
                continue;
            }
            ingestStixObject(readStixObject(reader), state);
        }
        reader.endArray();
        addResolvedStixKeywords(state);
    }

    private static StixFields readStixObject(JsonReader reader) throws IOException {
        StixFields fields = new StixFields();
        reader.beginObject();
        while (reader.hasNext()) {
            String name = reader.nextName();
            switch (name) {
                case "type" -> fields.type = nextStringOrSkip(reader);
                case "id" -> fields.id = nextStringOrSkip(reader);
                case "name" -> fields.name = nextStringOrSkip(reader);
                case "pattern" -> fields.pattern = nextStringOrSkip(reader);
                case "relationship_type" -> fields.relationshipType = nextStringOrSkip(reader);
                case "source_ref" -> fields.sourceRef = nextStringOrSkip(reader);
                case "target_ref" -> fields.targetRef = nextStringOrSkip(reader);
                default -> reader.skipValue();
            }
        }
        reader.endObject();
        return fields;
    }

    private static void ingestStixObject(StixFields fields, StixFileState state) {
        if (fields.type == null) return;
        switch (fields.type) {
            case "malware" -> {
                if (fields.id == null) return;
                String name = fields.name != null ? fields.name.trim() : "";
                if (!name.isEmpty()) {
                    state.malwareById.put(fields.id, name);
                }
            }
            case "indicator" -> {
                ParsedPattern parsed = parsePattern(fields.pattern);
                if (parsed == null) return;
                state.indicators.add(new PendingIndicator(fields.id, parsed.type, parsed.value));
            }
            case "relationship" -> {
                if (!"indicates".equals(fields.relationshipType)) return;
                if (fields.sourceRef == null || fields.targetRef == null) return;
                state.indicates.add(new StixIndicates(fields.sourceRef, fields.targetRef));
            }
        }
    }

    private void addResolvedStixKeywords(StixFileState state) {
        String fallback = uniqueMalware(state.malwareById);
        Map<String, String> malwareByIndicator = new HashMap<>();
        for (StixIndicates rel : state.indicates) {
            String name = state.malwareById.get(rel.malwareId);
            if (name == null) continue;
            malwareByIndicator.putIfAbsent(rel.indicatorId, name);
        }
        for (PendingIndicator indicator : state.indicators) {
            String malware = indicator.id != null ? malwareByIndicator.get(indicator.id) : null;
            if (malware == null) {
                malware = fallback;
            }
            addKeyword(indicator.type, indicator.value, malware);
        }
    }

    private static String uniqueMalware(Map<String, String> malwareById) {
        Set<String> names = new HashSet<>(malwareById.values());
        return names.size() == 1 ? names.iterator().next() : null;
    }

    private void readMvtCollections(JsonReader reader) throws IOException {
        reader.beginArray();
        while (reader.hasNext()) {
            if (reader.peek() != JsonToken.BEGIN_OBJECT) {
                reader.skipValue();
                continue;
            }
            reader.beginObject();
            while (reader.hasNext()) {
                IndicatorType type = typeForKey(reader.nextName());
                if (type == null) {
                    reader.skipValue();
                } else if (reader.peek() == JsonToken.BEGIN_ARRAY) {
                    reader.beginArray();
                    while (reader.hasNext()) {
                        addKeyword(type, nextScalarOrNull(reader));
                    }
                    reader.endArray();
                } else {
                    addKeyword(type, nextScalarOrNull(reader));
                }
            }
            reader.endObject();
        }
        reader.endArray();
    }

    private static String nextScalarOrNull(JsonReader reader) throws IOException {
        switch (reader.peek()) {
            case STRING:
            case NUMBER:
                return reader.nextString();
            case BOOLEAN:
                return String.valueOf(reader.nextBoolean());
            default:
                reader.skipValue();
                return null;
        }
    }

    private void addKeyword(IndicatorType type, String value) {
        addKeyword(type, value, null);
    }

    private void addKeyword(IndicatorType type, String value, String malware) {
        if (value == null || value.trim().isEmpty()) return;
        Map<String, LinkedHashSet<String>> byKeyword = malwareByKeyword.get(type);
        if (byKeyword == null) return;
        String keyword = value.toLowerCase(Locale.ROOT);
        LinkedHashSet<String> families = byKeyword.computeIfAbsent(keyword, k -> {
            Trie.TrieBuilder builder = trieBuilders.get(type);
            if (builder != null) {
                builder.addKeyword(k);
            }
            return new LinkedHashSet<>();
        });
        if (malware != null && !malware.isEmpty()) {
            families.add(malware);
        }
    }

    /** Build the Aho-Corasick tries from the builders. */
    private void buildTries() {
        trieBuilders.forEach((type, builder) -> tries.put(type, builder.build()));
    }

    /** Parse a single STIX comparison like {@code [domain-name:value = 'evil.com']}. */
    private static ParsedPattern parsePattern(String pattern) {
        if (pattern == null) return null;
        Matcher matcher = STIX_EQUALITY_PATTERN.matcher(pattern.trim());
        if (!matcher.matches()) return null;
        IndicatorType type = typeForKey(matcher.group("key"));
        if (type == null) return null;
        String value = STIX_STRING_ESCAPE.matcher(matcher.group("value")).replaceAll("$1");
        return new ParsedPattern(type, value);
    }

    /** Match string against loaded indicators. */
    public List<Detection> matchString(String s, IndicatorType type) {
        if (s == null) return Collections.emptyList();

        Map<String, LinkedHashSet<String>> byKeyword = malwareByKeyword.get(type);
        if (byKeyword == null) return Collections.emptyList();

        Trie trie = tries.get(type);
        if (trie == null) {
            return matchExact(s, type, byKeyword);
        }

        List<Detection> detections = new ArrayList<>();
        for (Emit e : trie.parseText(s)) {
            addDetections(detections, byKeyword.get(e.getKeyword()), type, s);
        }
        return detections;
    }

    private List<Detection> matchExact(
            String s, IndicatorType type, Map<String, LinkedHashSet<String>> byKeyword) {
        String haystackLower = s.toLowerCase(Locale.ROOT);
        LinkedHashSet<String> families = byKeyword.get(haystackLower);
        if (families != null) {
            List<Detection> detections = new ArrayList<>(1);
            addDetections(detections, families, type, s);
            return detections;
        }
        if (type != IndicatorType.PROCESS) {
            return Collections.emptyList();
        }
        int n = haystackLower.length();
        if (n < PROCESS_COMM_TRUNCATED_MIN || n > PROCESS_COMM_TRUNCATED_MAX) {
            return Collections.emptyList();
        }
        List<Detection> detections = new ArrayList<>();
        for (Map.Entry<String, LinkedHashSet<String>> entry : byKeyword.entrySet()) {
            String keyword = entry.getKey();
            if (keyword.length() > n && keyword.startsWith(haystackLower)) {
                addDetections(detections, entry.getValue(), type, s);
            }
        }
        return detections;
    }

    private static void addDetections(
            List<Detection> detections,
            LinkedHashSet<String> families,
            IndicatorType type,
            String s) {
        if (families == null || families.isEmpty()) {
            detections.add(new Detection(DetectionType.IOC_MATCH, "", type.name(), s));
            return;
        }
        for (String family : families) {
            detections.add(new Detection(DetectionType.IOC_MATCH, family, type.name(), s));
        }
    }

    private static String nextStringOrSkip(JsonReader reader) throws IOException {
        if (reader.peek() != JsonToken.STRING) {
            reader.skipValue();
            return null;
        }
        return reader.nextString();
    }

    private static final class StixFileState {
        final Map<String, String> malwareById = new LinkedHashMap<>();
        final List<PendingIndicator> indicators = new ArrayList<>();
        final List<StixIndicates> indicates = new ArrayList<>();
    }

    private static final class PendingIndicator {
        final String id;
        final IndicatorType type;
        final String value;

        PendingIndicator(String id, IndicatorType type, String value) {
            this.id = id;
            this.type = type;
            this.value = value;
        }
    }

    private static final class ParsedPattern {
        final IndicatorType type;
        final String value;

        ParsedPattern(IndicatorType type, String value) {
            this.type = type;
            this.value = value;
        }
    }

    private static final class StixIndicates {
        final String indicatorId;
        final String malwareId;

        StixIndicates(String indicatorId, String malwareId) {
            this.indicatorId = indicatorId;
            this.malwareId = malwareId;
        }
    }

    private static final class StixFields {
        String type;
        String id;
        String name;
        String pattern;
        String relationshipType;
        String sourceRef;
        String targetRef;
    }
}
