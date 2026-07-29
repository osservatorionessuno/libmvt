package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.loadTestIndicators;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.streamArtifact;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.streamRecords;

public class DumpsysPackageActivitiesTest {

    @Test
    public void testParsing() throws Exception {
        List<Object> parsed = streamRecords(
                DumpsysPackageActivities::new,
                "dumpsys.txt",
                ResourcesUtils.readResource("android_data/dumpsys_packages.txt"));
        assertEquals(4, parsed.size());

        @SuppressWarnings("unchecked")
        Map<String, String> first = (Map<String, String>) parsed.get(0);
        assertEquals("com.samsung.android.app.social", first.get("package_name"));
        assertEquals("com.samsung.android.app.social/.feed.FeedsActivity", first.get("activity"));
    }

    @Test
    public void testIocCheck() throws Exception {
        DumpsysPackageActivities dpa = streamArtifact(
                DumpsysPackageActivities::new,
                "dumpsys.txt",
                ResourcesUtils.readResource("android_data/dumpsys_packages.txt"),
                loadTestIndicators());

        assertEquals(0, dpa.detected.size());
    }
}
