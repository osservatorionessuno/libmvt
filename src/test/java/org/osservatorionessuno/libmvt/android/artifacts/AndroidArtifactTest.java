package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;

import java.io.InputStream;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class AndroidArtifactTest {

    private static final class TestArtifact extends AndroidArtifact {
        @Override
        public List<String> paths() {
            return List.of();
        }

        @Override
        public void parse(org.osservatorionessuno.libmvt.common.AbstractInput artifactInput) {
        }

        @Override
        public void checkIndicators() {
        }

        boolean extractSection(InputStream content, String startPrefix, java.util.function.Consumer<String> block)
                throws Exception {
            return extractDumpsysSection(content, startPrefix, block);
        }
    }

    @Test
    public void testExtractDumpsysSection() throws Exception {
        TestArtifact artifact = new TestArtifact();
        StringBuilder section = new StringBuilder();
        try (InputStream dumpsys = ResourcesUtils.readResource("androidqf/dumpsys.txt")) {
            assertTrue(artifact.extractSection(
                    dumpsys,
                    "package:",
                    line -> section.append(line).append('\n')));
        }
        assertTrue(section.toString().contains("Receiver Resolver Table:"));
        assertFalse(section.toString().contains("DUMP OF SERVICE platform_compat:"));
    }
}
