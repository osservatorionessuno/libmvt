package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;
import org.osservatorionessuno.libmvt.common.AbstractInput;

import java.io.InputStream;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.runIocCheck;

public class DumpsysPlatformCompatTest {

    @Test
    public void testParsing() throws Exception {
        DumpsysPlatformCompat pc = new DumpsysPlatformCompat();
        InputStream data = ResourcesUtils.readResource("android_data/dumpsys_platform_compat.txt");
        pc.parse(new AbstractInput("dumpsys.txt", data) {});
        assertEquals(2, pc.getResults().size());

        @SuppressWarnings("unchecked")
        Map<String, String> first = (Map<String, String>) pc.getResults().get(0);
        assertEquals("org.torproject.torbrowser", first.get("package_name"));
    }

    @Test
    public void testIocCheck() throws Exception {
        DumpsysPlatformCompat pc = new DumpsysPlatformCompat();
        InputStream data = ResourcesUtils.readResource("android_data/dumpsys_platform_compat.txt");
        pc.parse(new AbstractInput("dumpsys.txt", data) {});

        runIocCheck(pc);

        assertEquals(0, pc.detected.size());
    }
}
