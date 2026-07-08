package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;
import org.osservatorionessuno.libmvt.common.AbstractInput;
import org.osservatorionessuno.libmvt.common.AlertLevel;
import org.osservatorionessuno.libmvt.common.JvmMapStringResolver;

import java.io.InputStream;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class SELinuxTest {

    private static SELinux parse(String resource) throws Exception {
        SELinux selinux = new SELinux();
        selinux.setStringResolver(new JvmMapStringResolver());
        try (InputStream data = ResourcesUtils.readResource(resource)) {
            selinux.parse(new AbstractInput("selinux.txt", data) {});
        }
        return selinux;
    }

    @Test
    public void testParsingEnforcing() throws Exception {
        SELinux selinux = parse("androidqf/selinux_enforcing.txt");
        assertEquals(1, selinux.getResults().size());

        @SuppressWarnings("unchecked")
        Map<String, String> rec = (Map<String, String>) selinux.getResults().get(0);
        assertEquals("enforcing", rec.get("status"));

        selinux.checkIndicators();
        assertTrue(selinux.detected.isEmpty());
    }

    @Test
    public void testParsingPermissive() throws Exception {
        SELinux selinux = parse("androidqf/selinux_permissive.txt");
        assertEquals(1, selinux.getResults().size());

        @SuppressWarnings("unchecked")
        Map<String, String> rec = (Map<String, String>) selinux.getResults().get(0);
        assertEquals("permissive", rec.get("status"));

        selinux.checkIndicators();
        assertEquals(1, selinux.detected.size());
        assertEquals(AlertLevel.HIGH, selinux.detected.get(0).getLevel());
        assertTrue(selinux.detected.get(0).getContext().contains("permissive"));
    }
}
