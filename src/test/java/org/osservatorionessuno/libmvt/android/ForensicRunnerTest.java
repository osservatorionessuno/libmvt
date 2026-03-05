package org.osservatorionessuno.libmvt.android;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.common.Artifact;
import org.osservatorionessuno.libmvt.common.Indicators;
import org.osservatorionessuno.libmvt.common.JvmMapStringResolver;

import java.io.File;
import java.nio.file.Paths;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class ForensicRunnerTest {

    @Test
    public void testRunAllModules() throws Exception {
        File dir = Paths.get("src", "test", "resources", "androidqf").toFile();
        File iocDir = Paths.get("src", "test", "resources", "iocs").toFile();

        Indicators ind = new Indicators();
        ind.loadFromDirectory(iocDir);

        ForensicRunner runner = new ForensicRunner(new JvmMapStringResolver());
        runner.setIndicators(ind);

        Map<String, Artifact> res = runner.streamLegacyAnalysisFromDirectory(dir);

        // Keys are the source file names (legacy directory mode).
        assertTrue(res.containsKey("ps.txt"));
        Artifact proc = res.get("ps.txt");
        assertNotNull(proc);
        assertTrue(proc.getResults().size() > 0);

        assertTrue(res.containsKey("getprop.txt"));
        assertNotNull(res.get("getprop.txt"));
        assertTrue(res.get("getprop.txt").getResults().size() > 0);
    }

    @Test
    public void testRunSingleModule() throws Exception {
        File dir = Paths.get("src", "test", "resources", "androidqf").toFile();

        ForensicRunner runner = new ForensicRunner(new JvmMapStringResolver());
        Map<String, Artifact> res = runner.streamLegacyAnalysisFromDirectory(dir);
        Artifact art = res.get("getprop.txt");

        assertNotNull(art);
        assertTrue(art.getResults().size() > 0);
    }
}
