package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;
import org.osservatorionessuno.libmvt.common.AlertLevel;
import org.osservatorionessuno.libmvt.common.DetectionType;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetection;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionValueContains;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.loadTestIndicators;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.streamArtifact;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.streamRecords;

public class ANRTest {

    private static final String ANR_PATH = "FS/data/anr/anr_2026-03-28-01-20-41-432";

    @Test
    public void testParsing() throws Exception {
        List<Object> parsed = streamRecords(
                ANR::new,
                ANR_PATH,
                ResourcesUtils.readResource("android_data/anr_process.txt"));
        assertEquals(1, parsed.size());

        @SuppressWarnings("unchecked")
        Map<String, Object> rec = (Map<String, Object>) parsed.get(0);
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
        ANR anr;
        try (var data = ResourcesUtils.readResource("android_data/anr_process.txt")) {
            anr = streamArtifact(ANR::new, ANR_PATH, data, loadTestIndicators());
        }

        assertFalse(anr.detected.isEmpty());
        assertDetection(anr.detected, DetectionType.ANR, AlertLevel.LOW);
        assertDetectionValueContains(anr.detected, DetectionType.ANR, "org.thoughtcrime.securesms");
    }
}
