package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;
import org.osservatorionessuno.libmvt.common.AbstractInput;
import org.osservatorionessuno.libmvt.common.DetectionType;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionCount;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionValueContains;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.runIocCheck;

public class DumpsysBatteryHistoryTest {

    @Test
    public void testParsing() throws Exception {
        DumpsysBatteryHistory bh = new DumpsysBatteryHistory();
        String data = ResourcesUtils.readResourceString("android_data/dumpsys_battery.txt");
        bh.parse(new AbstractInput("dumpsys.txt", new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8))) {});
        assertEquals(5, bh.getResults().size());

        @SuppressWarnings("unchecked")
        Map<String, String> first = (Map<String, String>) bh.getResults().get(0);
        assertEquals("com.samsung.android.app.reminder", first.get("package_name"));

        @SuppressWarnings("unchecked")
        Map<String, String> second = (Map<String, String>) bh.getResults().get(1);
        assertEquals("end_job", second.get("event"));

        @SuppressWarnings("unchecked")
        Map<String, String> third = (Map<String, String>) bh.getResults().get(2);
        assertEquals("start_top", third.get("event"));
        assertEquals("u0a280", third.get("uid"));
        assertEquals("com.whatsapp", third.get("package_name"));

        @SuppressWarnings("unchecked")
        Map<String, String> fourth = (Map<String, String>) bh.getResults().get(3);
        assertEquals("end_top", fourth.get("event"));

        @SuppressWarnings("unchecked")
        Map<String, String> fifth = (Map<String, String>) bh.getResults().get(4);
        assertEquals("com.sec.android.app.launcher", fifth.get("package_name"));
    }

    @Test
    public void testIocCheck() throws Exception {
        DumpsysBatteryHistory bh = new DumpsysBatteryHistory();
        String data = ResourcesUtils.readResourceString("android_data/dumpsys_battery.txt");
        bh.parse(new AbstractInput("dumpsys.txt", new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8))) {});

        runIocCheck(bh);

        assertEquals(0, bh.detected.size());
    }
}
