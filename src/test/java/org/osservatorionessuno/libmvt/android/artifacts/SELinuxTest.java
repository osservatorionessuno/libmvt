package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;
import org.osservatorionessuno.libmvt.common.AlertLevel;
import org.osservatorionessuno.libmvt.common.DetectionType;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetection;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionValue;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.parseAndroidArtifact;

public class SELinuxTest {

    @Test
    public void testParsingEnforcing() throws Exception {
        SELinux selinux = parseAndroidArtifact(
                SELinux::new,
                "selinux.txt",
                ResourcesUtils.readResource("androidqf/selinux_enforcing.txt"));
        assertEquals(1, selinux.getResults().size());

        @SuppressWarnings("unchecked")
        Map<String, String> rec = (Map<String, String>) selinux.getResults().get(0);
        assertEquals("enforcing", rec.get("status"));

        selinux.checkIndicators();
        assertTrue(selinux.detected.isEmpty());
    }

    @Test
    public void testParsingPermissive() throws Exception {
        SELinux selinux = parseAndroidArtifact(
                SELinux::new,
                "selinux.txt",
                ResourcesUtils.readResource("androidqf/selinux_permissive.txt"));
        assertEquals(1, selinux.getResults().size());

        @SuppressWarnings("unchecked")
        Map<String, String> rec = (Map<String, String>) selinux.getResults().get(0);
        assertEquals("permissive", rec.get("status"));

        selinux.checkIndicators();
        assertEquals(1, selinux.detected.size());
        assertDetection(selinux.detected, DetectionType.SELINUX_STATUS, AlertLevel.HIGH);
        assertDetectionValue(selinux.detected, DetectionType.SELINUX_STATUS, List.of("permissive"));
    }
}
