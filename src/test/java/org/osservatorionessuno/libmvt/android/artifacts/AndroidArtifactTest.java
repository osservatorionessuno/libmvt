package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

public class AndroidArtifactTest {

    @Test
    public void testExtractDumpsysSection() throws Exception {
        String dumpsys = new String(
                ResourcesUtils.readResourceBytes("androidqf/dumpsys.txt"),
                StandardCharsets.UTF_8
        );
        // TODO

        //String section = AndroidArtifact.extractDumpsysSection(dumpsys, "DUMP OF SERVICE package:");
        //assertNotNull(section);
        //assertTrue(section.contains("Receiver Resolver Table:"));
        //assertFalse(section.contains("DUMP OF SERVICE platform_compat:"));
    }
}
