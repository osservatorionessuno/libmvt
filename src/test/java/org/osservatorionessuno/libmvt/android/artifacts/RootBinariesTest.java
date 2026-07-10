package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;
import org.osservatorionessuno.libmvt.common.AlertLevel;
import org.osservatorionessuno.libmvt.common.DetectionType;

import static org.junit.jupiter.api.Assertions.*;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetection;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionValueContains;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.parseAndroidArtifact;

public class RootBinariesTest {

    @Test
    public void testParsingJson() throws Exception {
        RootBinaries rb = parseAndroidArtifact(
                RootBinaries::new,
                "root_binaries.json",
                ResourcesUtils.readResource("androidqf/root_binaries.json"));
        assertEquals(2, rb.getResults().size());
        assertEquals("/system/xbin/su", rb.getResults().get(0));
        assertEquals("/data/local/tmp/unknown_root_file", rb.getResults().get(1));
    }

    @Test
    public void testParsingProtobuf() throws Exception {
        RootBinaries rb = parseAndroidArtifact(
                RootBinaries::new,
                "root_binaries.pb",
                ResourcesUtils.readResource("androidqf/root_binaries.pb"));
        assertEquals(2, rb.getResults().size());
        assertEquals("/system/xbin/su", rb.getResults().get(0));
        assertEquals("/data/local/tmp/unknown_root_file", rb.getResults().get(1));
    }

    @Test
    public void testKnownAndUnknownBinaries() throws Exception {
        RootBinaries rb = parseAndroidArtifact(
                RootBinaries::new,
                "root_binaries.json",
                ResourcesUtils.readResource("androidqf/root_binaries.json"));
        rb.checkIndicators();

        assertEquals(2, rb.detected.size());
        assertDetection(rb.detected, DetectionType.ROOT_BINARIES, AlertLevel.HIGH);
        assertDetectionValueContains(rb.detected, DetectionType.ROOT_BINARIES, "SuperUser binary");
        assertDetectionValueContains(rb.detected, DetectionType.ROOT_BINARIES, "unknown root file");
    }
}
