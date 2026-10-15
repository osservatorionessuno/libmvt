package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;
import org.osservatorionessuno.libmvt.common.Detection;
import org.osservatorionessuno.libmvt.common.DetectionType;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionCount;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.streamArtifact;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.streamRecords;

public class DumpsysSettingsTest {

    @Test
    public void testParsing() throws Exception {
        List<Object> parsed = streamRecords(
                DumpsysSettings::new,
                "dumpsys.txt",
                ResourcesUtils.readResource("android_data/dumpsys_settings.txt"));

        assertEquals(6, parsed.size());
        assertSetting(parsed.get(0), "global", "package_verifier_enable", "0", "android");
        assertSetting(parsed.get(1), "global", "package_verifier_user_consent", "1", "android");
        assertSetting(parsed.get(2), "secure", "accessibility_enabled", "1", "com.android.shell");
        assertSetting(parsed.get(3), "secure", "lock_screen_lock_after_timeout", "5000", "com.android.shell");
        assertSetting(
                parsed.get(4),
                "secure",
                "enabled_accessibility_services",
                "com.foo/.A\ncom.bar/.B",
                "android");
        assertSetting(parsed.get(5), "system", "volume_music", "5", "android");
    }

    @Test
    public void testDangerousSettings() throws Exception {
        DumpsysSettings settings = streamArtifact(
                DumpsysSettings::new,
                "dumpsys.txt",
                ResourcesUtils.readResource("android_data/dumpsys_settings.txt"));

        assertDetectionCount(settings.detected, DetectionType.DANGEROUS_SETTINGS, 4);
        assertTrue(hasValue(settings.detected, List.of(
                "disabled Google Play Protect",
                "package_verifier_enable",
                "0")));
        assertTrue(hasValue(settings.detected, List.of(
                "enabled accessibility services",
                "accessibility_enabled",
                "1")));
        assertTrue(hasValue(settings.detected, List.of(
                "was modified by com.android.shell",
                "accessibility_enabled",
                "1")));
        assertTrue(hasValue(settings.detected, List.of(
                "was modified by com.android.shell",
                "lock_screen_lock_after_timeout",
                "5000")));
    }

    @SuppressWarnings("unchecked")
    private static void assertSetting(Object record, String namespace, String name, String value, String pkg) {
        Map<String, String> setting = (Map<String, String>) record;
        assertEquals(namespace, setting.get("namespace"));
        assertEquals(name, setting.get("name"));
        assertEquals(value, setting.get("value"));
        assertEquals(pkg, setting.get("pkg"));
    }

    private static boolean hasValue(List<Detection> detections, List<String> expected) {
        for (Detection detection : detections) {
            if (DetectionType.DANGEROUS_SETTINGS.getId().equals(detection.getId())
                    && expected.equals(detection.getValue())) {
                return true;
            }
        }
        return false;
    }
}
