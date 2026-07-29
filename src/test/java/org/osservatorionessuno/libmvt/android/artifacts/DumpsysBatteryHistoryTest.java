package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.loadTestIndicators;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.streamArtifact;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.streamRecords;

public class DumpsysBatteryHistoryTest {

    @Test
    public void testParsing() throws Exception {
        List<Object> parsed = streamRecords(
                DumpsysBatteryHistory::new,
                "dumpsys.txt",
                ResourcesUtils.readResource("android_data/dumpsys_battery.txt"));
        assertEquals(5, parsed.size());

        @SuppressWarnings("unchecked")
        Map<String, String> first = (Map<String, String>) parsed.get(0);
        assertEquals("com.samsung.android.app.reminder", first.get("package_name"));

        @SuppressWarnings("unchecked")
        Map<String, String> second = (Map<String, String>) parsed.get(1);
        assertEquals("end_job", second.get("event"));

        @SuppressWarnings("unchecked")
        Map<String, String> third = (Map<String, String>) parsed.get(2);
        assertEquals("start_top", third.get("event"));
        assertEquals("u0a280", third.get("uid"));
        assertEquals("com.whatsapp", third.get("package_name"));

        @SuppressWarnings("unchecked")
        Map<String, String> fourth = (Map<String, String>) parsed.get(3);
        assertEquals("end_top", fourth.get("event"));

        @SuppressWarnings("unchecked")
        Map<String, String> fifth = (Map<String, String>) parsed.get(4);
        assertEquals("com.sec.android.app.launcher", fifth.get("package_name"));
    }

    @Test
    public void testIocCheck() throws Exception {
        DumpsysBatteryHistory bh = streamArtifact(
                DumpsysBatteryHistory::new,
                "dumpsys.txt",
                ResourcesUtils.readResource("android_data/dumpsys_battery.txt"),
                loadTestIndicators());

        assertEquals(0, bh.detected.size());
    }
}
