package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;
import org.osservatorionessuno.libmvt.common.AlertLevel;
import org.osservatorionessuno.libmvt.common.DetectionType;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetection;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionValueContains;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.streamArtifact;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.streamRecords;

public class RootBinariesTest {

    @Test
    public void testParsingJson() throws Exception {
        List<Object> parsed = streamRecords(
                RootBinaries::new,
                "root_binaries.json",
                ResourcesUtils.readResource("androidqf/root_binaries.json"));
        assertEquals(2, parsed.size());
        assertEquals("/system/xbin/su", parsed.get(0));
        assertEquals("/data/local/tmp/unknown_root_file", parsed.get(1));
    }

    @Test
    public void testParsingJsonl() throws Exception {
        List<Object> parsed = streamRecords(
                RootBinaries::new,
                "root_binaries.jsonl",
                ResourcesUtils.readResource("androidqf/root_binaries.jsonl"));
        assertEquals(2, parsed.size());
        assertEquals("/system/xbin/su", parsed.get(0));
        assertEquals("/data/local/tmp/unknown_root_file", parsed.get(1));
    }

    @Test
    public void testKnownAndUnknownBinaries() throws Exception {
        RootBinaries rb = streamArtifact(
                RootBinaries::new,
                "root_binaries.json",
                ResourcesUtils.readResource("androidqf/root_binaries.json"));

        assertEquals(2, rb.detected.size());
        assertDetection(rb.detected, DetectionType.ROOT_BINARIES, AlertLevel.HIGH);
        assertDetectionValueContains(rb.detected, DetectionType.ROOT_BINARIES, "SuperUser binary");
        assertDetectionValueContains(rb.detected, DetectionType.ROOT_BINARIES, "unknown root file");
    }
}
