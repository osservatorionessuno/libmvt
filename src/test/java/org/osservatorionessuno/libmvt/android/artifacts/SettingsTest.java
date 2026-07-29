package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;
import org.osservatorionessuno.libmvt.common.DetectionType;

import java.io.InputStream;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionCount;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionValueContains;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.streamArtifact;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.streamRecords;

public class SettingsTest {

    @Test
    public void testParsing() throws Exception {
        List<Object> parsed;
        try (InputStream data = ResourcesUtils.readResource("androidqf/settings_secure.txt")) {
            parsed = streamRecords(Settings::new, "settings_secure.txt", data);
        }

        assertEquals(1, parsed.size());
        @SuppressWarnings("unchecked")
        Map<String, String> rec = (Map<String, String>) parsed.get(0);
        assertEquals("1", rec.get("accessibility_enabled"));
        assertEquals("0", rec.get("package_verifier_enable"));
    }

    @Test
    public void testDangerousSettings() throws Exception {
        Settings settings;
        try (InputStream data = ResourcesUtils.readResource("androidqf/settings_secure.txt")) {
            settings = streamArtifact(Settings::new, "settings_secure.txt", data);
        }

        assertEquals(2, settings.detected.size());
        assertDetectionCount(settings.detected, DetectionType.DANGEROUS_SETTINGS, 2);
        assertDetectionValueContains(settings.detected, DetectionType.DANGEROUS_SETTINGS, "accessibility_enabled");
        assertDetectionValueContains(settings.detected, DetectionType.DANGEROUS_SETTINGS, "package_verifier_enable");
    }
}
