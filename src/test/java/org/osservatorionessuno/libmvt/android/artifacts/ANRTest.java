package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.android.ArtifactModuleRegistry;
import org.osservatorionessuno.libmvt.ResourcesUtils;
import org.osservatorionessuno.libmvt.common.AbstractInput;
import org.osservatorionessuno.libmvt.common.AlertLevel;
import org.osservatorionessuno.libmvt.common.DetectionType;
import org.osservatorionessuno.libmvt.common.Indicators;
import org.osservatorionessuno.libmvt.common.JvmMapStringResolver;

import java.io.InputStream;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetection;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionValueContains;

public class ANRTest {

    @Test
    public void testParsing() throws Exception {
        ANR anr = new ANR();
        InputStream data = ResourcesUtils.readResource("android_data/anr_process.txt");
        anr.parse(new AbstractInput("FS/data/anr/anr_2026-03-28-01-20-41-432", data) {});

        assertEquals(1, anr.getResults().size());

        @SuppressWarnings("unchecked")
        Map<String, Object> rec = (Map<String, Object>) anr.getResults().get(0);
        assertEquals(
                "Input dispatching timed out (Application does not have a focused window).",
                rec.get("subject"));
        assertEquals(25749, rec.get("pid"));
        assertEquals("org.thoughtcrime.securesms", rec.get("package_name"));
        assertEquals("2026-03-28 01:20:41.313405", rec.get("timestamp"));
        assertEquals(
                "org.thoughtcrime.securesms",
                ((List<?>) rec.get("command_line")).get(0));
    }

    @Test
    public void testCheckIndicators() throws Exception {
        ANR anr = new ANR();
        anr.setStringResolver(new JvmMapStringResolver());
        try (var data = ResourcesUtils.readResource("android_data/anr_process.txt")) {
            anr.parse(new AbstractInput("FS/data/anr/anr_2026-03-28-01-20-41-432", data) {});
        }

        Indicators indicators = new Indicators();
        indicators.loadFromDirectory(
                java.nio.file.Paths.get("src", "test", "resources", "iocs").toFile());
        anr.setIndicators(indicators);
        anr.checkIndicators();

        assertFalse(anr.detected.isEmpty());
        assertDetection(anr.detected, DetectionType.ANR, AlertLevel.MEDIUM);
        assertDetectionValueContains(anr.detected, DetectionType.ANR, "org.thoughtcrime.securesms");
    }
}
