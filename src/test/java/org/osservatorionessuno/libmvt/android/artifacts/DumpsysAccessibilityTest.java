package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;
import org.osservatorionessuno.libmvt.common.Indicators;
import org.osservatorionessuno.libmvt.common.Indicators.IndicatorType;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class DumpsysAccessibilityTest {

    @Test
    public void testParsing() throws Exception {
        DumpsysAccessibility da = new DumpsysAccessibility();
        InputStream data = ResourcesUtils.readResource("android_data/dumpsys_accessibility.txt");
        da.parse(data);
        assertEquals(4, da.getResults().size());
        @SuppressWarnings("unchecked")
        Map<String, String> first = (Map<String, String>) da.getResults().get(0);
        assertEquals("com.android.settings", first.get("package_name"));
        assertEquals(
                "com.android.settings/com.samsung.android.settings.development.gpuwatch.GPUWatchInterceptor",
                first.get("service")
        );
    }

    @Test
    public void testParsingV14Format() throws Exception {
        DumpsysAccessibility da = new DumpsysAccessibility();
        InputStream data = ResourcesUtils.readResource("android_data/dumpsys_accessibility_v14_or_later.txt");
        da.parse(data);
        assertEquals(1, da.getResults().size());
        @SuppressWarnings("unchecked")
        Map<String, String> first = (Map<String, String>) da.getResults().get(0);
        assertEquals("com.malware.accessibility", first.get("package_name"));
        assertEquals("com.malware.service.malwareservice", first.get("service"));
    }

    @Test
    public void testIocCheck() throws Exception {
        DumpsysAccessibility da = new DumpsysAccessibility();
        InputStream data = ResourcesUtils.readResource("android_data/dumpsys_accessibility.txt");
        da.parse(data);

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
        da.setIndicators(indicators);
        da.checkIndicators();

        assertEquals(1, da.detected.size());
        assertTrue(da.detected.get(0).getContext().contains("APP_ID"));
    }
}
