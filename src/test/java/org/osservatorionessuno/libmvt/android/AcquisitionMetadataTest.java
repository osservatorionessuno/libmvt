package org.osservatorionessuno.libmvt.android;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.*;

public class AcquisitionMetadataTest {

    @TempDir
    Path tempDir;

    @Test
    public void testFromJsonBugbaneFormat() {
        AcquisitionMetadata meta = AcquisitionMetadata.fromJson("""
            {
              "uuid": "abc",
              "created": "2026-06-21T16:16:39.422656Z",
              "completed": "2026-06-21T16:19:17.634836Z",
              "bugbane_version": "0.2.0",
              "androidqf_version": "Bugbane-0.2.0"
            }
            """);

        assertEquals("2026-06-21T16:16:39.422656Z", meta.getCreated());
        assertEquals("2026-06-21T16:19:17.634836Z", meta.getCompleted());
        assertEquals("0.2.0", meta.getBugbaneVersion());
        assertEquals("Bugbane-0.2.0", meta.getAndroidqfVersion());
        assertEquals("2026-06-21 16:16:39 UTC", meta.getCreatedFormatted());
        assertEquals("2026-06-21 16:19:17 UTC", meta.getCompletedFormatted());
    }

    @Test
    public void testFromJsonAndroidqfFormatUsesStartedAndDropsZeroCompleted() {
        AcquisitionMetadata meta = AcquisitionMetadata.fromJson("""
            {
              "uuid": "abc",
              "started": "2025-12-08T14:10:15.142602Z",
              "completed": "0001-01-01T00:00:00Z",
              "androidqf_version": "v1.7.0-24-ge50ad47"
            }
            """);

        assertEquals("2025-12-08T14:10:15.142602Z", meta.getCreated());
        assertNull(meta.getCompleted());
        assertNull(meta.getBugbaneVersion());
        assertEquals("v1.7.0-24-ge50ad47", meta.getAndroidqfVersion());
    }

    @Test
    public void testFromJsonDropsZeroCompletedVariants() {
        assertNull(AcquisitionMetadata.fromJson(
                "{\"completed\":\"0001-01-01T00:00:00.000Z\"}").getCompleted());
        assertNull(AcquisitionMetadata.fromJson(
                "{\"completed\":\"0001-01-01T00:00:00+00:00\"}").getCompleted());
    }

    @Test
    public void testLoadFromDirectory() throws Exception {
        File dir = tempDir.toFile();
        File metaFile = new File(dir, "acquisition.json");
        java.nio.file.Files.writeString(
                metaFile.toPath(),
                """
                {"created":"2026-01-01T00:00:00Z","completed":"2026-01-01T01:00:00Z","bugbane_version":"1.0.0"}
                """);

        AcquisitionMetadata meta = AcquisitionMetadata.load(dir);
        assertNotNull(meta);
        assertEquals("2026-01-01T00:00:00Z", meta.getCreated());
        assertEquals("2026-01-01T01:00:00Z", meta.getCompleted());
        assertEquals("1.0.0", meta.getBugbaneVersion());
    }

    @Test
    public void testLoadFromZip() throws Exception {
        File zipFile = tempDir.resolve("acq.zip").toFile();
        try (ZipOutputStream zout = new ZipOutputStream(new FileOutputStream(zipFile))) {
            zout.putNextEntry(new ZipEntry("acquisition.json"));
            zout.write("""
                {"started":"2025-01-01T00:00:00Z","androidqf_version":"v1.0.0","completed":"2025-01-01T02:00:00Z"}
                """.getBytes(StandardCharsets.UTF_8));
            zout.closeEntry();
            zout.putNextEntry(new ZipEntry("getprop.txt"));
            zout.write("[ro.build.id]: [test]\n".getBytes(StandardCharsets.UTF_8));
            zout.closeEntry();
        }

        AcquisitionMetadata meta = AcquisitionMetadata.load(zipFile);
        assertNotNull(meta);
        assertEquals("2025-01-01T00:00:00Z", meta.getCreated());
        assertEquals("2025-01-01T02:00:00Z", meta.getCompleted());
        assertEquals("v1.0.0", meta.getAndroidqfVersion());
    }

    @Test
    public void testLoadMissingReturnsNull() {
        assertNull(AcquisitionMetadata.load(tempDir.toFile()));
    }
}
