package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.loadTestIndicators;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.streamArtifact;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.streamRecords;

public class DumpsysPlatformCompatTest {

    @Test
    public void testParsing() throws Exception {
        List<Object> parsed = streamRecords(
                DumpsysPlatformCompat::new,
                "dumpsys.txt",
                ResourcesUtils.readResource("android_data/dumpsys_platform_compat.txt"));
        assertEquals(2, parsed.size());

        @SuppressWarnings("unchecked")
        Map<String, String> first = (Map<String, String>) parsed.get(0);
        assertEquals("org.torproject.torbrowser", first.get("package_name"));
    }

    @Test
    public void testIocCheck() throws Exception {
        DumpsysPlatformCompat pc = streamArtifact(
                DumpsysPlatformCompat::new,
                "dumpsys.txt",
                ResourcesUtils.readResource("android_data/dumpsys_platform_compat.txt"),
                loadTestIndicators());

        assertEquals(0, pc.detected.size());
    }
}
