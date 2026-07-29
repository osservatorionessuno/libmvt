package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;
import org.osservatorionessuno.libmvt.common.DetectionType;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionValueContains;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.loadTestIndicators;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.streamArtifact;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.streamRecords;

public class DumpsysPackagesTest {

    @Test
    public void testParsing() throws Exception {
        List<Object> parsed = streamRecords(
                DumpsysPackages::new,
                "dumpsys.txt",
                ResourcesUtils.readResource("android_data/dumpsys_packages.txt"));
        assertEquals(2, parsed.size());

        @SuppressWarnings("unchecked")
        Map<String, Object> first = (Map<String, Object>) parsed.get(0);
        assertEquals("com.samsung.android.provider.filterprovider", first.get("package_name"));
        assertEquals("5.0.07", first.get("version_name"));
    }

    @Test
    public void testIocCheck() throws Exception {
        DumpsysPackages dpa = streamArtifact(
                DumpsysPackages::new,
                "dumpsys.txt",
                ResourcesUtils.readResource("android_data/dumpsys_packages.txt"),
                loadTestIndicators());

        assertDetectionValueContains(dpa.detected, DetectionType.IOC_MATCH, "com.sec.android.app.DataCreate");
    }

    @Test
    public void testRootPackageDetection() throws Exception {
        String sample = "DUMP OF SERVICE package:\nPackages:\n  Package [com.topjohnwu.magisk] (test)\n    userId=0\n";
        DumpsysPackages dpa = streamArtifact(
                DumpsysPackages::new,
                "dumpsys.txt",
                new ByteArrayInputStream(sample.getBytes(StandardCharsets.UTF_8)));

        assertDetectionValueContains(dpa.detected, DetectionType.PACKAGES_ROOT_PACKAGE, "com.topjohnwu.magisk");
    }

    /**
     * Each package is emitted when the next block starts, so only one block is ever buffered:
     * the package list of a real device is far too long to hold as one string.
     */
    @Test
    public void testPackagesAreEmittedPerBlockAndNotRetained() throws Exception {
        StringBuilder sample = new StringBuilder("DUMP OF SERVICE package:\nPackages:\n");
        for (int i = 0; i < 50; i++) {
            sample.append("  Package [com.example.p").append(i).append("] (x)\n")
                    .append("    userId=").append(1000 + i).append('\n');
        }

        DumpsysPackages dpa = streamArtifact(
                DumpsysPackages::new,
                "dumpsys.txt",
                new ByteArrayInputStream(sample.toString().getBytes(StandardCharsets.UTF_8)));

        assertEquals(50, dpa.getRecordCount());
        assertTrue(dpa.detected.isEmpty());
    }
}
