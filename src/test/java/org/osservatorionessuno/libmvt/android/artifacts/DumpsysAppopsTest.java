package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;
import org.osservatorionessuno.libmvt.common.AbstractInput;
import org.osservatorionessuno.libmvt.common.AlertLevel;
import org.osservatorionessuno.libmvt.common.DetectionType;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetection;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionValueContains;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.runIocCheck;

public class DumpsysAppopsTest {

    @Test
    public void testParsing() throws Exception {
        DumpsysAppops da = new DumpsysAppops();
        String data = ResourcesUtils.readResourceString("android_data/dumpsys_appops.txt");
        da.parse(new AbstractInput("dumpsys.txt", new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8))) {});
        assertEquals(14, da.getResults().size());

        @SuppressWarnings("unchecked")
        Map<String, Object> first = (Map<String, Object>) da.getResults().get(0);
        assertEquals("com.android.phone", first.get("package_name"));
        assertEquals("0", first.get("uid"));

        @SuppressWarnings("unchecked")
        List<?> perms = (List<?>) first.get("permissions");
        assertEquals(1, perms.size());

        @SuppressWarnings("unchecked")
        Map<String, Object> seventh = (Map<String, Object>) da.getResults().get(7);
        assertEquals("com.android.shell", seventh.get("package_name"));
        assertEquals("2000", seventh.get("uid"));
        perms = (List<?>) seventh.get("permissions");
        assertEquals(4, perms.size());
        assertEquals("allow", ((Map<String, Object>) perms.get(0)).get("access"));

        @SuppressWarnings("unchecked")
        Map<String, Object> twelfth = (Map<String, Object>) da.getResults().get(12);
        assertEquals(4, ((List<?>) twelfth.get("permissions")).size());
    }

    @Test
    public void testIocCheck() throws Exception {
        DumpsysAppops da = new DumpsysAppops();
        String data = ResourcesUtils.readResourceString("android_data/dumpsys_appops.txt");
        da.parse(new AbstractInput("dumpsys.txt", new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8))) {});

        runIocCheck(da);

        assertDetectionValueContains(da.detected, DetectionType.IOC_MATCH, "com.facebook.katana");
        assertDetection(da.detected, DetectionType.APPOPS_RISKY_PERMISSION, AlertLevel.MEDIUM);
        assertDetectionValueContains(da.detected, DetectionType.APPOPS_RISKY_PERMISSION, "REQUEST_INSTALL_PACKAGES");
        assertDetectionValueContains(da.detected, DetectionType.APPOPS_RISKY_PERMISSION, "2022-02-02 23:20:13.096");

        List<String> appopsTimestamps = da.detected.stream()
                .filter(d -> DetectionType.APPOPS_RISKY_PERMISSION.getId().equals(d.getId()))
                .map(d -> d.getValue().size() > 3 ? d.getValue().get(3) : "")
                .filter(ts -> !ts.isEmpty())
                .toList();
        List<String> sorted = appopsTimestamps.stream().sorted().toList();
        // yyyy-MM-dd HH:mm:ss.SSS sorts chronologically as plain strings
        assertEquals(sorted, appopsTimestamps, "APPOPS detections must be ordered by timestamp");
    }
}
