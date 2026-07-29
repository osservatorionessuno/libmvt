package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.loadTestIndicators;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.streamArtifact;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.streamRecords;

public class DumpsysDBInfoTest {

    @Test
    public void testParsing() throws Exception {
        List<Object> parsed = streamRecords(
                DumpsysDBInfo::new,
                "dumpsys.txt",
                ResourcesUtils.readResource("android_data/dumpsys_dbinfo.txt"));
        assertEquals(5, parsed.size());

        @SuppressWarnings("unchecked")
        Map<String, String> first = (Map<String, String>) parsed.get(0);
        assertEquals("executeForCursorWindow", first.get("action"));
        assertEquals("PRAGMA database_list;", first.get("sql"));
        assertEquals("/data/user/0/com.wssyncmldm/databases/idmsdk.db", first.get("path"));
    }

    @Test
    public void testIocCheck() throws Exception {
        DumpsysDBInfo dbi = streamArtifact(
                DumpsysDBInfo::new,
                "dumpsys.txt",
                ResourcesUtils.readResource("android_data/dumpsys_dbinfo.txt"),
                loadTestIndicators());

        assertEquals(0, dbi.detected.size());
    }
}
