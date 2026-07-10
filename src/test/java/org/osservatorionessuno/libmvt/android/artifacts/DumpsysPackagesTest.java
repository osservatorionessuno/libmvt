package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;
import org.osservatorionessuno.libmvt.common.AbstractInput;
import org.osservatorionessuno.libmvt.common.DetectionType;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionValueContains;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.runIocCheck;

public class DumpsysPackagesTest {

    @Test
    public void testParsing() throws Exception {
        DumpsysPackages dpa = new DumpsysPackages();
        String data = ResourcesUtils.readResourceString("android_data/dumpsys_packages.txt");
        dpa.parse(new AbstractInput("dumpsys.txt", new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8))) {});
        assertEquals(2, dpa.getResults().size());

        @SuppressWarnings("unchecked")
        Map<String, Object> first = (Map<String, Object>) dpa.getResults().get(0);
        assertEquals("com.samsung.android.provider.filterprovider", first.get("package_name"));
        assertEquals("5.0.07", first.get("version_name"));
    }

    @Test
    public void testIocCheck() throws Exception {
        DumpsysPackages dpa = new DumpsysPackages();
        String data = ResourcesUtils.readResourceString("android_data/dumpsys_packages.txt");
        dpa.parse(new AbstractInput("dumpsys.txt", new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8))) {});

        runIocCheck(dpa);

        assertDetectionValueContains(dpa.detected, DetectionType.IOC_MATCH, "com.sec.android.app.DataCreate");
    }

    @Test
    public void testRootPackageDetection() throws Exception {
        DumpsysPackages dpa = new DumpsysPackages();
        String sample = "DUMP OF SERVICE package:\nPackages:\n  Package [com.topjohnwu.magisk] (test)\n    userId=0\n";
        dpa.parse(new AbstractInput("dumpsys.txt", new ByteArrayInputStream(sample.getBytes(StandardCharsets.UTF_8))) {});
        dpa.checkIndicators();
        assertDetectionValueContains(dpa.detected, DetectionType.PACKAGES_ROOT_PACKAGE, "com.topjohnwu.magisk");
    }
}
