package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;
import org.osservatorionessuno.libmvt.common.AlertLevel;
import org.osservatorionessuno.libmvt.common.DetectionType;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetection;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionValue;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.streamArtifact;

public class SELinuxTest {

    @Test
    public void testParsingEnforcing() throws Exception {
        SELinux selinux = streamArtifact(
                SELinux::new,
                "selinux.txt",
                ResourcesUtils.readResource("androidqf/selinux_enforcing.txt"));

        assertEquals(1, selinux.getRecordCount());
        assertTrue(selinux.detected.isEmpty());
    }

    @Test
    public void testParsingPermissive() throws Exception {
        SELinux selinux = streamArtifact(
                SELinux::new,
                "selinux.txt",
                ResourcesUtils.readResource("androidqf/selinux_permissive.txt"));

        assertEquals(1, selinux.getRecordCount());
        assertEquals(1, selinux.detected.size());
        assertDetection(selinux.detected, DetectionType.SELINUX_STATUS, AlertLevel.HIGH);
        assertDetectionValue(selinux.detected, DetectionType.SELINUX_STATUS, List.of("permissive"));
    }
}
