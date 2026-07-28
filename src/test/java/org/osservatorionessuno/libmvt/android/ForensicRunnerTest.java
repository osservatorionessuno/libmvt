package org.osservatorionessuno.libmvt.android;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.common.Artifact;
import org.osservatorionessuno.libmvt.common.DetectionTestUtils;
import org.osservatorionessuno.libmvt.common.DetectionType;
import org.osservatorionessuno.libmvt.common.JvmMapStringResolver;
import org.osservatorionessuno.libmvt.common.ReopenableInput;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;

import static org.osservatorionessuno.libmvt.ResourcesUtils.readResourceBytes;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionValueContains;

import static org.junit.jupiter.api.Assertions.*;

public class ForensicRunnerTest {

    @Test
    public void testRunAllModules() throws Exception {
        File dir = Paths.get("src", "test", "resources", "androidqf").toFile();

        ForensicRunner runner = new ForensicRunner(new JvmMapStringResolver());
        runner.setIndicators(DetectionTestUtils.loadTestIndicators());

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

    @Test
    public void testGlobPathMatching() {
        assertFalse(ForensicRunner.findModuleIndices("FS/data/tombstones/tombstone_02.pb").isEmpty());
        assertFalse(ForensicRunner.findModuleIndices("FS/data/tombstones/tombstone_01").isEmpty());
        assertTrue(ForensicRunner.findModuleIndices("FS/data/tombstones/other_file.txt").isEmpty());
        assertFalse(ForensicRunner.findModuleIndices("getprop.txt").isEmpty());
        assertFalse(ForensicRunner.findModuleIndices("logs/anr_2026-03-28-01-20-41-432").isEmpty());
    }

    @Test
    public void testGlobPathAnalysisFromDirectory() throws Exception {
        File dir = Paths.get("src", "test", "resources", "android_data", "bugreport").toFile();

        ForensicRunner runner = new ForensicRunner(new JvmMapStringResolver());
        Map<String, Artifact> res = runner.streamLegacyAnalysisFromDirectory(dir);

        assertTrue(res.containsKey("FS/data/tombstones/tombstone_01"));
        Artifact tombstone = res.get("FS/data/tombstones/tombstone_01");
        assertNotNull(tombstone);
        assertTrue(tombstone.getResults().size() > 0);
    }

    @Test
    public void testCorruptArtifactDoesNotAbortScan() throws Exception {
        Path dir = java.nio.file.Files.createTempDirectory("mvt-corrupt-");
        // Declares a 200-byte record but supplies 2, so the module throws mid-parse.
        java.nio.file.Files.write(
                dir.resolve("root_binaries.pb"),
                new byte[] {(byte) 0xC8, 0x01, 0x0A, 0x02});
        java.nio.file.Files.writeString(dir.resolve("selinux.txt"), "Permissive\n");
        java.nio.file.Files.write(
                dir.resolve("getprop.txt"),
                readResourceBytes("androidqf/getprop.txt"));

        ForensicRunner runner = new ForensicRunner(new JvmMapStringResolver());
        Map<String, Artifact> res = runner.streamLegacyAnalysisFromDirectory(dir.toFile());

        // The healthy modules still run.
        assertTrue(res.containsKey("selinux.txt"));
        assertTrue(res.containsKey("getprop.txt"));
        assertTrue(res.get("getprop.txt").getResults().size() > 0);

        // The corrupt one parses nothing but reports the lost coverage.
        Artifact skipped = res.get("root_binaries.pb");
        assertNotNull(skipped);
        assertEquals(0, skipped.getResults().size());
        assertDetectionValueContains(
                skipped.detected, DetectionType.ARTIFACT_PARSE_FAILED, "RootBinaries");
    }

    @Test
    public void testOneFailingModuleKeepsTheOthersOnSharedPath() throws Exception {
        // dumpsys.txt fans out to every dumpsys module. The appops section is malformed
        // ("x" has no access parens, so DumpsysAppops throws on substring), while the
        // platform_compat section right after it is well formed.
        String dumpsys = """
                DUMP OF SERVICE appops:
                  Uid 0:
                    Package com.example:
                      REQUEST_INSTALL_PACKAGES x
                -------------------------------------------------------------------------------
                DUMP OF SERVICE platform_compat:
                  ChangeId(168419799; name=DOWNSCALED; rawOverrides={com.evil.app=true};)
                """;
        byte[] data = dumpsys.getBytes(java.nio.charset.StandardCharsets.UTF_8);

        ForensicRunner runner = new ForensicRunner(new JvmMapStringResolver());
        assertTrue(ForensicRunner.findModuleIndices("dumpsys.txt").size() > 1);

        Artifact art = runner.streamFileAnalysis(
                ReopenableInput.of("dumpsys.txt", () -> new ByteArrayInputStream(data)));

        // DumpsysAppops is dropped and reported; DumpsysPlatformCompat still contributes.
        assertNotNull(art);
        assertTrue(art.getResults().size() > 0);
        assertDetectionValueContains(
                art.detected, DetectionType.ARTIFACT_PARSE_FAILED, "DumpsysAppops");
    }

    @Test
    public void testStreamFileAnalysisWithReopenableInput() throws Exception {
        byte[] data = readResourceBytes("androidqf/dumpsys.txt");
        ReopenableInput input = ReopenableInput.of(
                "dumpsys.txt",
                () -> new ByteArrayInputStream(data));

        ForensicRunner runner = new ForensicRunner(new JvmMapStringResolver());
        List<Integer> indices = ForensicRunner.findModuleIndices("dumpsys.txt");
        assertTrue(indices.size() > 1);

        Artifact art = runner.streamFileAnalysis(input);
        assertNotNull(art);
        assertTrue(art.getResults().size() > 0);
    }

    @Test
    public void testStreamAnalysisWithReopenableInput() throws Exception {
        byte[] getprop = readResourceBytes("androidqf/getprop.txt");
        byte[] dumpsys = readResourceBytes("androidqf/dumpsys.txt");

        ForensicRunner runner = new ForensicRunner(new JvmMapStringResolver());
        Map<String, Artifact> res = runner.streamAnalysis(List.of(
                ReopenableInput.of("getprop.txt", () -> new ByteArrayInputStream(getprop)),
                ReopenableInput.of("dumpsys.txt", () -> new ByteArrayInputStream(dumpsys))
        ));

        assertTrue(res.containsKey("getprop.txt"));
        assertTrue(res.get("getprop.txt").getResults().size() > 0);
        assertTrue(res.containsKey("dumpsys.txt"));
        assertTrue(res.get("dumpsys.txt").getResults().size() > 0);
    }

}
