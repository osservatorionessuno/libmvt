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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Loads indicators from .json and .stix2 (JSON) files and matches strings.
 * Files are parsed as a stream (Gson's pull parser), never held in memory.
 * Keyword matching uses Aho-Corasick tries for efficient pattern matching.
 */
public class Indicators {
    private static final String TAG = "Indicators";

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

    /**
     * Configuration mapping indicator types to their JSON field keys and STIX pattern keys.
     * This makes it easy to add new indicator types without modifying the core logic.
     */
    private static final Map<IndicatorType, Set<String>> INDICATOR_CONFIG = new EnumMap<>(IndicatorType.class);
    private static final Map<String, IndicatorType> TYPE_BY_KEY = new HashMap<>();
    
    static {
        INDICATOR_CONFIG.put(IndicatorType.DOMAIN, Set.of("domain-name:value", "ipv4-addr:value"));
        INDICATOR_CONFIG.put(IndicatorType.URL, Set.of("url:value"));
        // TODO: Add support for 16-char truncated process names
        INDICATOR_CONFIG.put(IndicatorType.PROCESS, Set.of("process:name"));
        INDICATOR_CONFIG.put(IndicatorType.EMAIL, Set.of("email-addr:value"));
        INDICATOR_CONFIG.put(IndicatorType.APP_ID, Set.of("app:id"));
        INDICATOR_CONFIG.put(IndicatorType.PROPERTY, Set.of("android-property:name"));
        INDICATOR_CONFIG.put(IndicatorType.FILE_PATH, Set.of("file:path"));
        INDICATOR_CONFIG.put(IndicatorType.FILE_NAME, Set.of("file:name"));
        INDICATOR_CONFIG.put(IndicatorType.FILE_HASH_MD5, Set.of("file:hashes.md5"));
        INDICATOR_CONFIG.put(IndicatorType.FILE_HASH_SHA1, Set.of("file:hashes.sha1"));
        INDICATOR_CONFIG.put(IndicatorType.FILE_HASH_SHA256, Set.of("file:hashes.sha256"));
        INDICATOR_CONFIG.put(IndicatorType.APP_CERT_HASH_MD5, Set.of("app:cert.md5"));
        INDICATOR_CONFIG.put(IndicatorType.APP_CERT_HASH_SHA1, Set.of("app:cert.sha1"));
        INDICATOR_CONFIG.put(IndicatorType.APP_CERT_HASH_SHA256, Set.of("app:cert.sha256"));
        INDICATOR_CONFIG.put(IndicatorType.IOS_PROFILE_ID, Set.of("configuration-profile:id"));
        INDICATOR_CONFIG.forEach((type, keys) -> keys.forEach(key -> TYPE_BY_KEY.put(key, type)));
    }

    private final Map<IndicatorType, Trie.TrieBuilder> trieBuilders;
    private final Map<IndicatorType, Trie> tries;
    private StringResolver stringResolver = new JvmMapStringResolver();

    public Indicators() {
        this.trieBuilders = new EnumMap<>(IndicatorType.class);
        this.tries = new EnumMap<>(IndicatorType.class);

        // Initialize builders for all configured indicator types
        for (IndicatorType type : INDICATOR_CONFIG.keySet()) {
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
        reader.beginArray();
        while (reader.hasNext()) {
            if (reader.peek() != JsonToken.BEGIN_OBJECT) {
                reader.skipValue();
                continue;
            }
            String type = null;
            String pattern = null;
            reader.beginObject();
            while (reader.hasNext()) {
                String name = reader.nextName();
                if ("type".equals(name) && reader.peek() == JsonToken.STRING) {
                    type = reader.nextString();
                } else if ("pattern".equals(name) && reader.peek() == JsonToken.STRING) {
                    pattern = reader.nextString();
                } else {
                    reader.skipValue();
                }
            }
            reader.endObject();
            if ("indicator".equals(type)) {
                addPattern(pattern);
            }
        }
        reader.endArray();
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
                IndicatorType type = TYPE_BY_KEY.get(reader.nextName());
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
        Trie.TrieBuilder builder = trieBuilders.get(type);
        if (builder == null || value == null || value.trim().isEmpty()) return;
        builder.addKeyword(value.toLowerCase());
    }

    /** Build the Aho-Corasick tries from the builders. */
    private void buildTries() {
        for (Map.Entry<IndicatorType, Trie.TrieBuilder> entry : trieBuilders.entrySet()) {
            tries.put(entry.getKey(), entry.getValue().build());
        }
    }

    /** Parse a single STIX pattern like: "[domain-name:value = 'evil.com']" */
    private void addPattern(String pattern) {
        if (pattern == null) return;
        String p = pattern.trim();
        if (p.startsWith("[") && p.endsWith("]")) {
            p = p.substring(1, p.length() - 1);
        }
        String[] kv = p.split("=", 2);
        if (kv.length != 2) return;

        String key = kv[0].trim();
        String value = kv[1].trim();
        if (value.startsWith("'") && value.endsWith("'") && value.length() >= 2) {
            value = value.substring(1, value.length() - 1);
        }
        String vLower = value.toLowerCase();

        // Find which indicator type this STIX pattern key belongs to
        for (Map.Entry<IndicatorType, Set<String>> entry : INDICATOR_CONFIG.entrySet()) {
            Set<String> keys = entry.getValue();
            if (keys.contains(key)) {
                Trie.TrieBuilder builder = trieBuilders.get(entry.getKey());
                if (builder != null) {
                    builder.addKeyword(vLower);
                }
                // else: indicator type not supported (no Android Log on JVM)
                return;
            }
        }
    }

    /** Match string against loaded indicators. */
    public List<Detection> matchString(String s, IndicatorType type) {
        if (s == null) return Collections.emptyList();

        Trie trie = tries.get(type);
        if (trie == null) return Collections.emptyList();

        List<Detection> detections = new ArrayList<>();
        for (Emit e : trie.parseText(s)) {
            detections.add(new Detection(DetectionType.IOC_MATCH,
                type.name(), s));
        }

        return detections;
    }

    // --------- tiny JSON helper ----------
}
