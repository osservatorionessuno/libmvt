package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;
import org.osservatorionessuno.libmvt.common.AbstractInput;
import org.osservatorionessuno.libmvt.common.AlertLevel;
import org.osservatorionessuno.libmvt.common.DetectionType;
import org.osservatorionessuno.libmvt.common.JvmMapStringResolver;

import java.io.InputStream;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetection;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionValueContains;

public class MountsTest {

    private static Mounts parse(String path, InputStream data) throws Exception {
        Mounts mounts = new Mounts();
        mounts.setStringResolver(new JvmMapStringResolver());
        mounts.parse(new AbstractInput(path, data) {});
        return mounts;
    }

    @Test
    public void testParsingJson() throws Exception {
        Mounts mounts = parse("mounts.json", ResourcesUtils.readResource("androidqf/mounts.json"));
        assertEquals(3, mounts.getResults().size());

        @SuppressWarnings("unchecked")
        Map<String, Object> system = (Map<String, Object>) mounts.getResults().get(0);
        assertEquals("/system", system.get("mount_point"));
        assertEquals("ext4", system.get("filesystem_type"));
        assertFalse((Boolean) system.get("is_read_write"));

        @SuppressWarnings("unchecked")
        Map<String, Object> dataMount = (Map<String, Object>) mounts.getResults().get(1);
        assertEquals("/data", dataMount.get("mount_point"));
        assertTrue((Boolean) dataMount.get("is_read_write"));
    }

    @Test
    public void testParsingProtobuf() throws Exception {
        Mounts mounts = parse("mounts.pb", ResourcesUtils.readResource("androidqf/mounts.pb"));
        assertEquals(3, mounts.getResults().size());

        @SuppressWarnings("unchecked")
        Map<String, Object> product = (Map<String, Object>) mounts.getResults().get(2);
        assertEquals("/product", product.get("mount_point"));
        assertEquals("ext4", product.get("filesystem_type"));
        assertTrue((Boolean) product.get("is_read_write"));
    }

    @Test
    public void testCheckIndicators() throws Exception {
        Mounts mounts = parse("mounts.json", ResourcesUtils.readResource("androidqf/mounts.json"));
        mounts.checkIndicators();

        assertDetection(mounts.detected, DetectionType.MOUNTS_SYSTEM, AlertLevel.HIGH);
        assertDetectionValueContains(mounts.detected, DetectionType.MOUNTS_SYSTEM, "/product");
        assertDetection(mounts.detected, DetectionType.MOUNTS_SUSPICIOUS, AlertLevel.LOW);
        assertDetectionValueContains(mounts.detected, DetectionType.MOUNTS_SUSPICIOUS, "rw");
        assertDetection(mounts.detected, DetectionType.MOUNTS_DATA, AlertLevel.LOG);
        assertDetectionValueContains(mounts.detected, DetectionType.MOUNTS_DATA, "/data");
    }

    @Test
    public void testOptionsList() throws Exception {
        Mounts mounts = parse("mounts.json", ResourcesUtils.readResource("androidqf/mounts.json"));

        @SuppressWarnings("unchecked")
        List<String> options = (List<String>) ((Map<?, ?>) mounts.getResults().get(2)).get("options_list");
        assertTrue(options.contains("rw"));
        assertTrue(options.contains("relatime"));
    }
}
