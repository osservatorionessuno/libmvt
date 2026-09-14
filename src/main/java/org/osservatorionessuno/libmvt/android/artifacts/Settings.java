package org.osservatorionessuno.libmvt.android.artifacts;

import org.osservatorionessuno.libmvt.common.AbstractInput;
import org.osservatorionessuno.libmvt.common.Detection;
import org.osservatorionessuno.libmvt.common.DetectionType;

import java.util.*;
import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parser for Android settings. Reads the {@code settings_*.txt} key=value files, which
 * {@code cmd settings list} prints for user 0 only, and the {@code dumpsys settings} section,
 * which lists every user's rows with the recording package. Both yield one {@link Record} per row.
 */
public class Settings extends AndroidArtifact {
    private static class DangerousSetting {
        String key;
        String safeValue;
        String description;
    }

    private static final HashMap<String, DangerousSetting> DANGEROUS_SETTINGS = new HashMap<>();

    static {
        add("verifier_verify_adb_installs", "1", "disabled Google Play Services apps verification");
        add("package_verifier_enable", "1", "disabled Google Play Protect");
        add("package_verifier_state", "1", "disabled APK package verification");
        add("package_verifier_user_consent", "1", "disabled Google Play Protect");
        add("upload_apk_enable", "1", "disabled Google Play Protect");
        add("adb_install_need_confirm", "1", "disabled confirmation of adb apps installation");
        add("send_security_reports", "1", "disabled sharing of security reports");
        add("samsung_errorlog_agree", "1", "disabled sharing of crash logs with manufacturer");
        add("send_action_app_error", "1", "disabled applications errors reports");
        add("accessibility_enabled", "0", "enabled accessibility services");
    }

    private static void add(String key, String safeVal, String desc) {
        DangerousSetting ds = new DangerousSetting();
        ds.key = key; ds.safeValue = safeVal; ds.description = desc;
        DANGEROUS_SETTINGS.put(key, ds);
    }

    /** One settings row. Only {@code namespace}, {@code name} and {@code value} come from a key=value file. */
    public static final class Record {
        public String namespace;
        /** The Android user the row belongs to; null when the source does not say. */
        public String user;
        public String id;
        public String name;
        public String pkg;
        public String value;
        public String defaultValue;
        public String defaultSystemSet;
        public String tag;
        public String valuePreservedInRestore;
    }

    private static final String PRIMARY_USER = "0";

    // Field order SettingsProvider prints for a row. Some vendor builds end a row with
    // isValuePreservedInRestore: or a bare notPreservedInRestore token.
    private static final String[] SETTING_FIELDS = {
        "_id", "name", "pkg", "value", "default", "defaultSystemSet", "tag", "isValuePreservedInRestore",
    };
    private static final String NOT_PRESERVED_TOKEN = " notPreservedInRestore";

    // CONFIG, GLOBAL, SECURE, SYSTEM; an unknown block still starts its own namespace.
    private static final Pattern NAMESPACE_PATTERN =
            Pattern.compile("^([A-Z_]+) SETTINGS \\(user (\\d+)\\)$");

    @Override
    public List<String> paths() {
        List<String> paths = new ArrayList<>(
                List.of("settings_system.txt", "settings_secure.txt", "settings_global.txt"));
        paths.addAll(DumpsysArtifact.DUMPSYS_PATHS);
        return paths;
    }

    @Override
    public void parse(AbstractInput artifactInput) throws IOException {
        String fileName = artifactInput.path.replace('\\', '/');
        fileName = fileName.substring(fileName.lastIndexOf('/') + 1);
        if (fileName.startsWith("settings_") && fileName.endsWith(".txt")) {
            String namespace = fileName.substring("settings_".length(), fileName.length() - ".txt".length());
            parseKeyValues(artifactInput, namespace);
        } else {
            DumpsysState state = new DumpsysState();
            extractDumpsysSection(artifactInput.inputStream, " settings:", state::accept);
            state.flush();
        }
    }

    private void parseKeyValues(AbstractInput artifactInput, String namespace) throws IOException {
        forEachLine(artifactInput.inputStream, line -> {
            line = line.trim();
            int separator = line.indexOf('=');
            if (separator < 0) return;
            Record record = new Record();
            record.namespace = namespace;
            record.name = line.substring(0, separator);
            record.value = line.substring(separator + 1);
            emit(record);
        });
    }

    /** A row runs to the next {@code _id:} line, heading or blank line: values may span lines. */
    private final class DumpsysState {
        private String namespace;
        private String user;
        private final List<String> recordLines = new ArrayList<>();

        void accept(String line) {
            Matcher heading = NAMESPACE_PATTERN.matcher(line.trim());
            if (heading.matches()) {
                flush();
                namespace = heading.group(1).toLowerCase();
                user = heading.group(2);
                return;
            }

            if (line.startsWith("--------- ")) {
                // dumpsys closes the section with a duration trailer.
                flush();
                namespace = null;
                return;
            }

            if (namespace == null) return;

            if (line.trim().isEmpty()) {
                // Closes each block; the generation registry follows the last one.
                flush();
                return;
            }

            if (line.startsWith("_id:")) {
                flush();
                recordLines.add(line);
                return;
            }

            // The version: line precedes the rows; anything else continues the row being read.
            if (!recordLines.isEmpty()) recordLines.add(line);
        }

        void flush() {
            if (!recordLines.isEmpty()) {
                emit(buildRecord(namespace, user, recordLines));
            }
            recordLines.clear();
        }
    }

    private static Record buildRecord(String namespace, String user, List<String> recordLines) {
        String text = String.join("\n", recordLines);
        int end = text.length();
        while (end > 0 && Character.isWhitespace(text.charAt(end - 1))) end--;
        text = text.substring(0, end);
        // The bare token has no key: shape and is printed last.
        boolean notPreserved = text.endsWith(NOT_PRESERVED_TOKEN);
        String head = notPreserved ? text.substring(0, text.length() - NOT_PRESERVED_TOKEN.length()) : text;

        Map<String, String> fields = splitFields(head, SETTING_FIELDS);
        Record record = new Record();
        record.namespace = namespace;
        record.user = user;
        record.id = fields.get("_id");
        record.name = fields.get("name");
        record.pkg = fields.get("pkg");
        record.value = fields.get("value");
        record.defaultValue = fields.get("default");
        record.defaultSystemSet = fields.get("defaultSystemSet");
        record.tag = fields.get("tag");
        record.valuePreservedInRestore = notPreserved ? "false" : fields.get("isValuePreservedInRestore");
        return record;
    }

    /**
     * Splits the {@code key:value} fields of one row. Values are free-form and may contain spaces
     * and newlines, so a field runs up to the next key that is actually present; keys dumpsys did
     * not print are skipped.
     */
    static Map<String, String> splitFields(String text, String[] keys) {
        Map<String, String> fields = new HashMap<>();
        String key = keys[0];
        if (!text.startsWith(key + ":")) return fields;

        String remainder = text.substring(key.length() + 1);
        for (int i = 1; i < keys.length; i++) {
            String nextKey = keys[i];
            int at = remainder.indexOf(" " + nextKey + ":");
            if (at < 0) continue;
            fields.put(key, remainder.substring(0, at));
            key = nextKey;
            remainder = remainder.substring(at + nextKey.length() + 2);
        }
        fields.put(key, remainder);
        return fields;
    }

    @Override
    protected void checkRecord(Object record) {
        Record setting = (Record) record;
        DangerousSetting ds = DANGEROUS_SETTINGS.get(setting.name);
        if (ds == null || ds.safeValue.equals(setting.value)) return;

        List<String> value = new ArrayList<>(
                List.of(ds.description, setting.namespace, setting.name, String.valueOf(setting.value)));
        // Only non-primary users are labelled: the key=value files carry no user, and the same
        // value from both sources lets the grouping collapse the primary user's finding.
        if (setting.user != null && !PRIMARY_USER.equals(setting.user)) {
            value.add("user " + setting.user);
        }
        detected.add(new Detection(DetectionType.DANGEROUS_SETTINGS, value));
    }
}
