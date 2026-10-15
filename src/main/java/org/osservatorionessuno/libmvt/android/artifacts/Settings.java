package org.osservatorionessuno.libmvt.android.artifacts;

import org.osservatorionessuno.libmvt.common.AbstractInput;
import org.osservatorionessuno.libmvt.common.Detection;
import org.osservatorionessuno.libmvt.common.DetectionType;

import java.util.*;
import java.io.InputStream;
import java.io.IOException;

/** Parser for Android settings files. */
public class Settings extends AndroidArtifact {
    private static class DangerousSetting {
        String key;
        String safeValue;
        String description;
    }

    private static final HashMap<String, DangerousSetting> DANGEROUS_SETTINGS = new HashMap<>();

    // TODO: find a way to make the following fields translatable
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

    /** Description when [value] is unsafe for a known dangerous key, otherwise null. */
    static String getUnsafeSettingDescription(String key, String value) {
        if (key == null || value == null) return null;
        DangerousSetting ds = DANGEROUS_SETTINGS.get(key);
        if (ds == null || ds.safeValue.equals(value)) return null;
        return ds.description;
    }

    @Override
    public List<String> paths() {
        return List.of("settings_system.txt", "settings_secure.txt", "settings_global.txt");
    }

    @Override
    public void parse(AbstractInput artifactInput) throws IOException {
        Map<String, String> map = new HashMap<>();
        forEachLine(artifactInput.inputStream, line -> {
            line = line.trim();
            if (line.isEmpty() || !line.contains("=")) return;
            String[] parts = line.split("=", 2);
            map.put(parts[0], parts.length > 1 ? parts[1] : "");
        });

        // One record per settings file: a value is only dangerous relative to its key.
        emit(map);
    }

    @Override
    protected void checkRecord(Object record) {
        @SuppressWarnings("unchecked")
        Map<String, String> settings = (Map<String, String>) record;
        for (Map.Entry<String, String> entry : settings.entrySet()) {
            String description = getUnsafeSettingDescription(entry.getKey(), entry.getValue());
            if (description != null) {
                detected.add(new Detection(
                        DetectionType.DANGEROUS_SETTINGS,
                        description,
                        entry.getKey(),
                        entry.getValue()));
            }
        }
    }
}
