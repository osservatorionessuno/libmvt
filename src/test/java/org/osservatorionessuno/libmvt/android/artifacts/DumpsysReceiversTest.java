package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.loadTestIndicators;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.streamArtifact;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.streamRecords;

public class DumpsysReceiversTest {

    @Test
    public void testParsing() throws Exception {
        List<Object> parsed = streamRecords(
                DumpsysReceivers::new,
                "dumpsys.txt",
                ResourcesUtils.readResource("android_data/dumpsys_packages.txt"));
        assertEquals(4, parsed.size());

        @SuppressWarnings("unchecked")
        Map<String, String> first = (Map<String, String>) parsed.get(0);
        assertEquals("com.android.storagemanager.automatic.SHOW_NOTIFICATION", first.get("intent"));
        assertEquals("com.android.storagemanager", first.get("package_name"));
    }

    @Test
    public void testIocCheck() throws Exception {
        DumpsysReceivers dr = streamArtifact(
                DumpsysReceivers::new,
                "dumpsys.txt",
                ResourcesUtils.readResource("android_data/dumpsys_packages.txt"),
                loadTestIndicators());

        assertEquals(0, dr.detected.size());
    }
}
