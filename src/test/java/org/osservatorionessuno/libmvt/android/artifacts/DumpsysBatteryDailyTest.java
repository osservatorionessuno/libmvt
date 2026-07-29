package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;
import org.osservatorionessuno.libmvt.common.DetectionType;

import static org.junit.jupiter.api.Assertions.*;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionCount;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionValueContains;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.loadTestIndicators;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.streamArtifact;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.streamRecords;

public class DumpsysBatteryDailyTest {

    @Test
    public void testParsing() throws Exception {
        assertEquals(3, streamRecords(
                DumpsysBatteryDaily::new,
                "dumpsys.txt",
                ResourcesUtils.readResource("android_data/dumpsys_battery.txt")).size());
    }

    @Test
    public void testIocCheck() throws Exception {
        DumpsysBatteryDaily bd = streamArtifact(
                DumpsysBatteryDaily::new,
                "dumpsys.txt",
                ResourcesUtils.readResource("android_data/dumpsys_battery.txt"),
                loadTestIndicators());

        assertDetectionCount(bd.detected, DetectionType.IOC_MATCH, 1);
        assertDetectionValueContains(bd.detected, DetectionType.IOC_MATCH, "com.facebook.katana");
    }
}
