package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;
import org.osservatorionessuno.libmvt.common.AbstractInput;
import org.osservatorionessuno.libmvt.common.AlertLevel;
import org.osservatorionessuno.libmvt.common.JvmMapStringResolver;

import java.io.InputStream;

import static org.junit.jupiter.api.Assertions.*;

public class RootBinariesTest {

    private static RootBinaries parse(String path, InputStream data) throws Exception {
        RootBinaries rb = new RootBinaries();
        rb.setStringResolver(new JvmMapStringResolver());
        rb.parse(new AbstractInput(path, data) {});
        return rb;
    }

    @Test
    public void testParsingJson() throws Exception {
        RootBinaries rb = parse(
                "root_binaries.json",
                ResourcesUtils.readResource("androidqf/root_binaries.json"));
        assertEquals(2, rb.getResults().size());
        assertEquals("/system/xbin/su", rb.getResults().get(0));
        assertEquals("/data/local/tmp/unknown_root_file", rb.getResults().get(1));
    }

    @Test
    public void testParsingProtobuf() throws Exception {
        RootBinaries rb = parse(
                "root_binaries.pb",
                ResourcesUtils.readResource("androidqf/root_binaries.pb"));
        assertEquals(2, rb.getResults().size());
        assertEquals("/system/xbin/su", rb.getResults().get(0));
        assertEquals("/data/local/tmp/unknown_root_file", rb.getResults().get(1));
    }

    @Test
    public void testKnownAndUnknownBinaries() throws Exception {
        RootBinaries rb = parse(
                "root_binaries.json",
                ResourcesUtils.readResource("androidqf/root_binaries.json"));
        rb.checkIndicators();

        assertEquals(2, rb.detected.size());
        assertEquals(AlertLevel.HIGH, rb.detected.get(0).getLevel());
        assertTrue(rb.detected.get(0).getContext().contains("SuperUser binary"));
        assertTrue(rb.detected.get(1).getContext().contains("unknown root file"));
    }
}
