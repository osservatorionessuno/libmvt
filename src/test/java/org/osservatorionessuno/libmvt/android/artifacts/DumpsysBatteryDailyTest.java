package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;
import org.osservatorionessuno.libmvt.common.AbstractInput;
import org.osservatorionessuno.libmvt.common.DetectionType;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionCount;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionValueContains;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.runIocCheck;

public class DumpsysBatteryDailyTest {

    @Test
    public void testParsing() throws Exception {
        DumpsysBatteryDaily bd = new DumpsysBatteryDaily();
        String data = ResourcesUtils.readResourceString("android_data/dumpsys_battery.txt");
        bd.parse(new AbstractInput("dumpsys.txt", new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8))) {});
        assertEquals(3, bd.getResults().size());
    }

    @Test
    public void testIocCheck() throws Exception {
        DumpsysBatteryDaily bd = new DumpsysBatteryDaily();
        String data = ResourcesUtils.readResourceString("android_data/dumpsys_battery.txt");
        bd.parse(new AbstractInput("dumpsys.txt", new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8))) {});

        runIocCheck(bd);

        assertDetectionCount(bd.detected, DetectionType.IOC_MATCH, 1);
        assertDetectionValueContains(bd.detected, DetectionType.IOC_MATCH, "com.facebook.katana");
    }
}
