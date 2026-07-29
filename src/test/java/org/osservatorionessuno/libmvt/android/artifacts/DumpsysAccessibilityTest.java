package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;
import org.osservatorionessuno.libmvt.common.DetectionType;
import org.osservatorionessuno.libmvt.common.Indicators;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionCount;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionValueContains;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.streamArtifact;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.streamRecords;

public class DumpsysAccessibilityTest {

    @Test
    public void testParsing() throws Exception {
        List<Object> parsed = streamRecords(
                DumpsysAccessibility::new,
                "dumpsys.txt",
                ResourcesUtils.readResource("android_data/dumpsys_accessibility.txt"));
        assertEquals(4, parsed.size());

        @SuppressWarnings("unchecked")
        Map<String, String> first = (Map<String, String>) parsed.get(0);
        assertEquals("com.android.settings", first.get("package_name"));
        assertEquals(
                "com.android.settings/com.samsung.android.settings.development.gpuwatch.GPUWatchInterceptor",
                first.get("service")
        );
    }

    @Test
    public void testParsingV14Format() throws Exception {
        List<Object> parsed = streamRecords(
                DumpsysAccessibility::new,
                "dumpsys.txt",
                ResourcesUtils.readResource("android_data/dumpsys_accessibility_v14_or_later.txt"));
        assertEquals(1, parsed.size());

        @SuppressWarnings("unchecked")
        Map<String, String> first = (Map<String, String>) parsed.get(0);
        assertEquals("com.malware.accessibility", first.get("package_name"));
        assertEquals("com.malware.service.malwareservice", first.get("service"));
    }

    @Test
    public void testIocCheck() throws Exception {
        File tempDir = new File(System.getProperty("java.io.tmpdir"),
                "libmvt-test-iocs-" + System.currentTimeMillis());
        if (!tempDir.mkdirs() && !tempDir.isDirectory()) {
            throw new IOException("Unable to create temp IOC directory: " + tempDir);
        }

        // Copy bundled IOC files into the temp directory.
        File srcDir = Paths.get("src", "test", "resources", "iocs").toFile();
        File[] srcFiles = srcDir.listFiles();
        if (srcFiles != null) {
            for (File f : srcFiles) {
                if (!f.isFile()) continue;
                File dest = new File(tempDir, f.getName());
                try (FileInputStream in = new FileInputStream(f);
                     FileOutputStream out = new FileOutputStream(dest)) {
                    byte[] buf = new byte[8192];
                    int n;
                    while ((n = in.read(buf)) >= 0) {
                        out.write(buf, 0, n);
                    }
                }
            }
        }

        // Write an extra IOC json file into the temp directory.
        File extra = new File(tempDir, "extra.json");
        try (BufferedWriter bw = new BufferedWriter(
                new OutputStreamWriter(new FileOutputStream(extra), StandardCharsets.UTF_8))) {
            bw.write("{\"indicators\":[{\"app:id\":[\"com.sec.android.app.camera\"]}]}");
        }

        Indicators indicators = new Indicators();
        indicators.loadFromDirectory(tempDir);

        DumpsysAccessibility da = streamArtifact(
                DumpsysAccessibility::new,
                "dumpsys.txt",
                ResourcesUtils.readResource("android_data/dumpsys_accessibility.txt"),
                indicators);

        assertDetectionCount(da.detected, DetectionType.IOC_MATCH, 1);
        assertDetectionValueContains(da.detected, DetectionType.IOC_MATCH, "com.sec.android.app.camera");
    }
}
