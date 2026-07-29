package org.osservatorionessuno.libmvt.android.parsers;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/** Builds repackaged APKs: original signer certificate, broken signature. */
final class ApkTamperUtils {

    private ApkTamperUtils() {}

    /**
     * Rewrites {@code apk} with the contents of one entry replaced, keeping {@code META-INF}.
     * The v1 digests no longer match and the v2/v3 signing block is dropped, so verification
     * fails while the signer certificate is still recoverable — a repackaged app.
     */
    static byte[] repackageWithTamperedEntry(File apk, String entryName) throws Exception {
        byte[] original = Files.readAllBytes(apk.toPath());
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        boolean tampered = false;
        try (ZipInputStream zin = new ZipInputStream(new ByteArrayInputStream(original));
                ZipOutputStream zout = new ZipOutputStream(out)) {
            ZipEntry entry;
            while ((entry = zin.getNextEntry()) != null) {
                byte[] data = zin.readAllBytes();
                if (entry.getName().equals(entryName)) {
                    data = "TAMPERED".getBytes(StandardCharsets.UTF_8);
                    tampered = true;
                }
                zout.putNextEntry(new ZipEntry(entry.getName()));
                zout.write(data);
                zout.closeEntry();
            }
        }
        if (!tampered) {
            throw new IllegalArgumentException("No " + entryName + " in " + apk);
        }
        return out.toByteArray();
    }

    /** Same as {@link #repackageWithTamperedEntry}, written to a temporary file. */
    static File repackageWithTamperedEntryToFile(File apk, String entryName) throws Exception {
        byte[] bytes = repackageWithTamperedEntry(apk, entryName);
        File out = Files.createTempFile("mvt-repackaged-", ".apk").toFile();
        out.deleteOnExit();
        try (FileOutputStream fos = new FileOutputStream(out)) {
            fos.write(bytes);
        }
        return out;
    }
}
