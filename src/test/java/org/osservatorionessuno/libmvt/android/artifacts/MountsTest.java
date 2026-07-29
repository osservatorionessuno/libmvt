package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;
import org.osservatorionessuno.libmvt.common.AlertLevel;
import org.osservatorionessuno.libmvt.common.DetectionType;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetection;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionValueContains;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.streamArtifact;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.streamRecords;

public class MountsTest {

    @Test
    public void testParsingJson() throws Exception {
        List<Object> parsed = streamRecords(
                Mounts::new,
                "mounts.json",
                ResourcesUtils.readResource("androidqf/mounts.json"));
        assertEquals(3, parsed.size());

        @SuppressWarnings("unchecked")
        Map<String, Object> system = (Map<String, Object>) parsed.get(0);
        assertEquals("/system", system.get("mount_point"));
        assertEquals("ext4", system.get("filesystem_type"));
        assertFalse((Boolean) system.get("is_read_write"));

        @SuppressWarnings("unchecked")
        Map<String, Object> dataMount = (Map<String, Object>) parsed.get(1);
        assertEquals("/data", dataMount.get("mount_point"));
        assertTrue((Boolean) dataMount.get("is_read_write"));
    }

    @Test
    public void testParsingProtobuf() throws Exception {
        List<Object> parsed = streamRecords(
                Mounts::new,
                "mounts.pb",
                ResourcesUtils.readResource("androidqf/mounts.pb"));
        assertEquals(3, parsed.size());

        @SuppressWarnings("unchecked")
        Map<String, Object> product = (Map<String, Object>) parsed.get(2);
        assertEquals("/product", product.get("mount_point"));
        assertEquals("ext4", product.get("filesystem_type"));
        assertTrue((Boolean) product.get("is_read_write"));
    }

    @Test
    public void testCheckIndicators() throws Exception {
        Mounts mounts = streamArtifact(
                Mounts::new,
                "mounts.json",
                ResourcesUtils.readResource("androidqf/mounts.json"));

        assertDetection(mounts.detected, DetectionType.MOUNTS_SYSTEM, AlertLevel.HIGH);
        assertDetectionValueContains(mounts.detected, DetectionType.MOUNTS_SYSTEM, "/product");
        assertDetection(mounts.detected, DetectionType.MOUNTS_SUSPICIOUS, AlertLevel.LOW);
        assertDetectionValueContains(mounts.detected, DetectionType.MOUNTS_SUSPICIOUS, "rw");
        assertDetection(mounts.detected, DetectionType.MOUNTS_DATA, AlertLevel.LOG);
        assertDetectionValueContains(mounts.detected, DetectionType.MOUNTS_DATA, "/data");
    }

    @Test
    public void testOptionsList() throws Exception {
        List<Object> parsed = streamRecords(
                Mounts::new,
                "mounts.json",
                ResourcesUtils.readResource("androidqf/mounts.json"));

        @SuppressWarnings("unchecked")
        List<String> options = (List<String>) ((Map<?, ?>) parsed.get(2)).get("options_list");
        assertTrue(options.contains("rw"));
        assertTrue(options.contains("relatime"));
    }
}
