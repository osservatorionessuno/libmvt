package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;
import org.osservatorionessuno.libmvt.common.AbstractInput;

import java.io.InputStream;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.runIocCheck;

public class DumpsysPackageActivitiesTest {

    @Test
    public void testParsing() throws Exception {
        DumpsysPackageActivities dpa = new DumpsysPackageActivities();
        InputStream data = ResourcesUtils.readResource("android_data/dumpsys_packages.txt");
        dpa.parse(new AbstractInput("dumpsys.txt", data) {});
        assertEquals(4, dpa.getResults().size());

        @SuppressWarnings("unchecked")
        Map<String, String> first = (Map<String, String>) dpa.getResults().get(0);
        assertEquals("com.samsung.android.app.social", first.get("package_name"));
        assertEquals("com.samsung.android.app.social/.feed.FeedsActivity", first.get("activity"));
    }

    @Test
    public void testIocCheck() throws Exception {
        DumpsysPackageActivities dpa = new DumpsysPackageActivities();
        InputStream data = ResourcesUtils.readResource("android_data/dumpsys_packages.txt");
        dpa.parse(new AbstractInput("dumpsys.txt", data) {});

        runIocCheck(dpa);

        assertEquals(0, dpa.detected.size());
    }
}
