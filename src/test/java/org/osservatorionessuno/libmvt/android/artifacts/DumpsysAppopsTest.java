package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.common.AbstractInput;
import org.osservatorionessuno.libmvt.common.Indicators;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.List;
import java.util.Map;

import org.osservatorionessuno.libmvt.common.DetectionType;
import org.osservatorionessuno.libmvt.common.AlertLevel;

import static org.junit.jupiter.api.Assertions.*;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetection;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionValueContains;

public class DumpsysAppopsTest {

    private String readResource(String name) throws Exception {
        Path path = Paths.get("src", "test", "resources", name);
        StringBuilder sb = new StringBuilder(8192);
        try (BufferedReader br = java.nio.file.Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            char[] buf = new char[4096];
            int n;
            while ((n = br.read(buf)) >= 0) sb.append(buf, 0, n);
        }
        return sb.toString();
    }

    @Test
    public void testParsing() throws Exception {
        DumpsysAppops da = new DumpsysAppops();
        String data = readResource("android_data/dumpsys_appops.txt");
        da.parse(new AbstractInput("dumpsys.txt", new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8))) {});
        assertEquals(13, da.getResults().size());

        @SuppressWarnings("unchecked")
        Map<String, Object> first = (Map<String, Object>) da.getResults().get(0);
        assertEquals("com.android.phone", first.get("package_name"));
        assertEquals("0", first.get("uid"));

        @SuppressWarnings("unchecked")
        List<?> perms = (List<?>) first.get("permissions");
        assertEquals(1, perms.size());

        @SuppressWarnings("unchecked")
        Map<String, Object> seventh = (Map<String, Object>) da.getResults().get(6);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> plist = (List<Map<String, Object>>) seventh.get("permissions");
        @SuppressWarnings("unchecked")
        Map<String, Object> secondPerm = plist.get(1);
        @SuppressWarnings("unchecked")
        List<?> entries = (List<?>) secondPerm.get("entries");
        assertEquals(1, entries.size());

        @SuppressWarnings("unchecked")
        Map<String, Object> eleventh = (Map<String, Object>) da.getResults().get(11);
        assertEquals(4, ((List<?>) eleventh.get("permissions")).size());
    }

    @Test
    public void testIocCheck() throws Exception {
        DumpsysAppops da = new DumpsysAppops();
        String data = readResource("android_data/dumpsys_appops.txt");
        da.parse(new AbstractInput("dumpsys.txt", new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8))) {});

        Indicators indicators = new Indicators();
        indicators.loadFromDirectory(
                Paths.get("src", "test", "resources", "iocs").toFile()
        );
        da.setIndicators(indicators);
        da.checkIndicators();

        assertDetectionValueContains(da.detected, DetectionType.IOC_MATCH, "com.facebook.katana");
        assertDetection(da.detected, DetectionType.APPOPS_RISKY_PERMISSION, AlertLevel.MEDIUM);
        assertDetectionValueContains(da.detected, DetectionType.APPOPS_RISKY_PERMISSION, "REQUEST_INSTALL_PACKAGES");
    }
}
