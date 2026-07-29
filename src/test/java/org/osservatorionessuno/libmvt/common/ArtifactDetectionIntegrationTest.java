package org.osservatorionessuno.libmvt.common;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;
import org.osservatorionessuno.libmvt.android.artifacts.GetProp;
import org.osservatorionessuno.libmvt.android.artifacts.RootBinaries;

import java.io.InputStream;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionValueContains;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.loadTestIndicators;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.streamArtifact;

public class ArtifactDetectionIntegrationTest {

    @Test
    public void fromArtifactsToJsonArray() throws Exception {
        RootBinaries rootBinaries;
        try (InputStream data = ResourcesUtils.readResource("androidqf/root_binaries.json")) {
            rootBinaries = streamArtifact(RootBinaries::new, "root_binaries.json", data);
        }

        GetProp getProp;
        try (InputStream data = ResourcesUtils.readResource("androidqf/getprop.txt")) {
            getProp = streamArtifact(GetProp::new, "getprop.txt", data, loadTestIndicators());
        }

        assertDetectionValueContains(
                rootBinaries.detected, DetectionType.ROOT_BINARIES, "/system/xbin/su");
        assertDetectionValueContains(
                getProp.detected, DetectionType.IOC_MATCH, "dalvik.vm.appimageformat");

        Map<String, Artifact> artifacts = new LinkedHashMap<>();
        artifacts.put("root_binaries.json", rootBinaries);
        artifacts.put("getprop.txt", getProp);

        List<GroupedDetection> grouped = GroupedDetection.fromArtifacts(artifacts);
        JSONArray json = GroupedDetection.toJsonArray(grouped, new JvmMapStringResolver());

        assertEquals(2, grouped.size());
        assertEquals(2, json.length());

        JSONObject rootGroup = findGroup(json, DetectionType.ROOT_BINARIES.getId());
        assertEquals("HIGH", rootGroup.getString("level"));
        assertFalse(rootGroup.getString("title").isEmpty());
        assertFalse(rootGroup.getString("context").isEmpty());
        assertFalse(rootGroup.has("count"));

        JSONArray rootDetections = rootGroup.getJSONArray("detections");
        assertEquals(2, rootDetections.length());
        JSONObject rootEntry = rootDetections.getJSONObject(0);
        assertEquals("root_binaries.json", rootEntry.getString("file"));
        assertEquals("/system/xbin/su", rootEntry.getJSONArray("value").getString(0));
        assertEquals("SuperUser binary", rootEntry.getJSONArray("value").getString(1));
        assertFalse(rootEntry.has("context"));

        JSONObject iocGroup = findGroup(json, DetectionType.IOC_MATCH.getId());
        assertEquals("CRITICAL", iocGroup.getString("level"));
        assertFalse(iocGroup.getString("title").isEmpty());
        assertFalse(iocGroup.getString("context").isEmpty());

        JSONArray iocDetections = iocGroup.getJSONArray("detections");
        assertEquals(1, iocDetections.length());
        JSONObject iocEntry = iocDetections.getJSONObject(0);
        assertEquals("getprop.txt", iocEntry.getString("file"));
        assertTrue(iocEntry.getJSONArray("value").getString(1).contains("dalvik.vm.appimageformat"));
    }

    private static JSONObject findGroup(JSONArray array, String id) {
        for (int i = 0; i < array.length(); i++) {
            JSONObject obj = array.getJSONObject(i);
            if (id.equals(obj.getString("id"))) {
                return obj;
            }
        }
        throw new AssertionError("no group with id=" + id);
    }
}
