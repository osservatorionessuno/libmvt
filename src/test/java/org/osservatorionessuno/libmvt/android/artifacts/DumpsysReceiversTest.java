package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;
import org.osservatorionessuno.libmvt.common.Indicators;

import java.io.InputStream;
import java.nio.file.Paths;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class DumpsysReceiversTest {

    @Test
    public void testParsing() throws Exception {
        DumpsysReceivers dr = new DumpsysReceivers();
        InputStream data = ResourcesUtils.readResource("android_data/dumpsys_packages.txt");
        dr.parse(data);
        assertEquals(4, dr.getResults().size());

        @SuppressWarnings("unchecked")
        Map<String, String> first = (Map<String, String>) dr.getResults().get(0);
        assertEquals("com.android.storagemanager.automatic.SHOW_NOTIFICATION", first.get("intent"));
        assertEquals("com.android.storagemanager", first.get("package_name"));
    }

    @Test
    public void testIocCheck() throws Exception {
        DumpsysReceivers dr = new DumpsysReceivers();
        InputStream data = ResourcesUtils.readResource("android_data/dumpsys_packages.txt");
        dr.parse(data);

        Indicators ind = new Indicators();
        ind.loadFromDirectory(
                Paths.get("src", "test", "resources", "iocs").toFile()
        );
        dr.setIndicators(ind);
        dr.checkIndicators();

        assertEquals(0, dr.detected.size());
    }
}
