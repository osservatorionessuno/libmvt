package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;
import org.osservatorionessuno.libmvt.common.AbstractInput;
import org.osservatorionessuno.libmvt.common.DetectionType;
import org.osservatorionessuno.libmvt.common.JvmMapStringResolver;

import java.io.InputStream;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionCount;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionValueContains;

public class SettingsTest {

    @Test
    public void testParsing() throws Exception {
        Settings settings = new Settings();
        try (InputStream data = ResourcesUtils.readResource("androidqf/settings_secure.txt")) {
            settings.parse(new AbstractInput("settings_secure.txt", data) {});
        }

        assertEquals(1, settings.getResults().size());
        @SuppressWarnings("unchecked")
        Map<String, String> rec = (Map<String, String>) settings.getResults().get(0);
        assertEquals("1", rec.get("accessibility_enabled"));
        assertEquals("0", rec.get("package_verifier_enable"));
    }

    @Test
    public void testDangerousSettings() throws Exception {
        Settings settings = new Settings();
        settings.setStringResolver(new JvmMapStringResolver());
        try (InputStream data = ResourcesUtils.readResource("androidqf/settings_secure.txt")) {
            settings.parse(new AbstractInput("settings_secure.txt", data) {});
        }
        settings.checkIndicators();

        assertEquals(2, settings.detected.size());
        assertDetectionCount(settings.detected, DetectionType.DANGEROUS_SETTINGS, 2);
        assertDetectionValueContains(settings.detected, DetectionType.DANGEROUS_SETTINGS, "accessibility_enabled");
        assertDetectionValueContains(settings.detected, DetectionType.DANGEROUS_SETTINGS, "package_verifier_enable");
    }
}
