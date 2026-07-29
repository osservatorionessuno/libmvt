package org.osservatorionessuno.libmvt.android;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.common.Artifact;
import org.osservatorionessuno.libmvt.common.DetectionTestUtils;
import org.osservatorionessuno.libmvt.common.DetectionType;
import org.osservatorionessuno.libmvt.common.JvmMapStringResolver;
import org.osservatorionessuno.libmvt.common.ReopenableInput;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.osservatorionessuno.libmvt.ResourcesUtils.readResourceBytes;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionValueContains;

import static org.junit.jupiter.api.Assertions.*;

public class ForensicRunnerTest {

    private static final String TOMBSTONE_KEY = "bugreport.zip/FS/data/tombstones/tombstone_01";

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
    public void testIsAnalyzable() {
        assertTrue(ForensicRunner.isAnalyzable("bugreport.zip"));
        assertTrue(ForensicRunner.isAnalyzable("path/to/Bugreport.ZIP"));
        assertTrue(ForensicRunner.isAnalyzable("getprop.txt"));
        assertFalse(ForensicRunner.isAnalyzable("unknown.bin"));
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
                        ReopenableInput.of("dumpsys.txt", () -> new ByteArrayInputStream(data)))
                .get("dumpsys.txt");

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

        Map<String, Artifact> res = runner.streamFileAnalysis(input);
        assertTrue(res.containsKey("dumpsys.txt"));
        assertTrue(res.get("dumpsys.txt").getResults().size() > 0);
    }

    @Test
    public void testStreamAnalysisFromZip() throws Exception {
        File sourceDir = Paths.get("src", "test", "resources", "androidqf").toFile();
        File zipFile = File.createTempFile("androidqf", ".zip");
        zipFile.deleteOnExit();

        try (ZipOutputStream zipOut = new ZipOutputStream(new FileOutputStream(zipFile))) {
            for (File file : sourceDir.listFiles()) {
                if (!file.isFile()) {
                    continue;
                }
                zipOut.putNextEntry(new ZipEntry(file.getName()));
                zipOut.write(readResourceBytes("androidqf/" + file.getName()));
                zipOut.closeEntry();
            }
        }

        ForensicRunner runner = new ForensicRunner(new JvmMapStringResolver());
        runner.setIndicators(DetectionTestUtils.loadTestIndicators());
        Map<String, Artifact> res = runner.streamAnalysisFromZip(zipFile);

        assertTrue(res.containsKey("getprop.txt"));
        assertTrue(res.get("getprop.txt").getResults().size() > 0);
    }

    @Test
    public void testNestedBugreportZipFromOuterZip() throws Exception {
        byte[] bugreportBytes = zipBugreportFixture();
        File outerZip = File.createTempFile("androidqf-with-bugreport", ".zip");
        outerZip.deleteOnExit();

        try (ZipOutputStream zipOut = new ZipOutputStream(new FileOutputStream(outerZip))) {
            zipOut.putNextEntry(new ZipEntry("getprop.txt"));
            zipOut.write(readResourceBytes("androidqf/getprop.txt"));
            zipOut.closeEntry();
            zipOut.putNextEntry(new ZipEntry("bugreport.zip"));
            zipOut.write(bugreportBytes);
            zipOut.closeEntry();
        }

        ForensicRunner runner = new ForensicRunner(new JvmMapStringResolver());
        Map<String, Artifact> res = runner.streamAnalysisFromZip(outerZip);

        assertTrue(res.containsKey("getprop.txt"));
        assertTrue(res.containsKey(TOMBSTONE_KEY));
        assertTrue(res.get(TOMBSTONE_KEY).getResults().size() > 0);
    }

    @Test
    public void testStreamFileAnalysisExpandsBugreportZip() throws Exception {
        byte[] bugreportBytes = zipBugreportFixture();
        ReopenableInput input = ReopenableInput.of(
                "bugreport.zip",
                () -> new ByteArrayInputStream(bugreportBytes));

        ForensicRunner runner = new ForensicRunner(new JvmMapStringResolver());
        Map<String, Artifact> res = runner.streamFileAnalysis(input);

        assertTrue(res.containsKey(TOMBSTONE_KEY));
        assertTrue(res.get(TOMBSTONE_KEY).getResults().size() > 0);
    }

    @Test
    public void testDirectoryModeExpandsBugreportZip() throws Exception {
        Path tempDir = Files.createTempDirectory("androidqf-bugreport-dir");
        tempDir.toFile().deleteOnExit();
        Path bugreportZip = tempDir.resolve("bugreport.zip");
        Files.write(bugreportZip, zipBugreportFixture());
        bugreportZip.toFile().deleteOnExit();

        ForensicRunner runner = new ForensicRunner(new JvmMapStringResolver());
        Map<String, Artifact> res = runner.streamLegacyAnalysisFromDirectory(tempDir.toFile());

        assertTrue(res.containsKey(TOMBSTONE_KEY));
        assertTrue(res.get(TOMBSTONE_KEY).getResults().size() > 0);
    }

    @Test
    public void testNestedZipReopensWantedEntriesAndSkipsTheRest() throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ZipOutputStream zipOut = new ZipOutputStream(bos)) {
            zipOut.putNextEntry(new ZipEntry("dumpsys.txt"));
            zipOut.write(readResourceBytes("androidqf/dumpsys.txt"));
            zipOut.closeEntry();
            zipOut.putNextEntry(new ZipEntry("getprop.txt"));
            zipOut.write(readResourceBytes("androidqf/getprop.txt"));
            zipOut.closeEntry();
            // No module asks for this one, so it must never be opened, let alone read.
            zipOut.putNextEntry(new ZipEntry("FS/data/junk.bin"));
            zipOut.write(new byte[4096]);
            zipOut.closeEntry();
        }
        byte[] bugreportBytes = bos.toByteArray();

        AtomicInteger opens = new AtomicInteger();
        ReopenableInput input = ReopenableInput.of("bugreport.zip", () -> {
            opens.incrementAndGet();
            return new ByteArrayInputStream(bugreportBytes);
        });

        ForensicRunner runner = new ForensicRunner(new JvmMapStringResolver());
        Map<String, Artifact> res = runner.streamFileAnalysis(input);

        assertTrue(res.containsKey("bugreport.zip/dumpsys.txt"));
        assertTrue(res.containsKey("bugreport.zip/getprop.txt"));
        assertFalse(res.containsKey("bugreport.zip/FS/data/junk.bin"));
        assertTrue(res.get("bugreport.zip/dumpsys.txt").getResults().size() > 0);

        // One pass to list the entries, then one reopen per module: nothing is buffered, and
        // junk.bin costs no opens at all.
        int expectedOpens = 1
                + ForensicRunner.findModuleIndices("dumpsys.txt").size()
                + ForensicRunner.findModuleIndices("getprop.txt").size();
        assertEquals(expectedOpens, opens.get());
    }

    private static byte[] zipBugreportFixture() throws IOException {
        Path root = Paths.get("src", "test", "resources", "android_data", "bugreport");
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ZipOutputStream zipOut = new ZipOutputStream(bos)) {
            Files.walk(root)
                    .filter(Files::isRegularFile)
                    .forEach(path -> {
                        try {
                            String entryName = root.relativize(path).toString().replace('\\', '/');
                            zipOut.putNextEntry(new ZipEntry(entryName));
                            zipOut.write(Files.readAllBytes(path));
                            zipOut.closeEntry();
                        } catch (IOException e) {
                            throw new RuntimeException(e);
                        }
                    });
        }
        return bos.toByteArray();
    }
}
