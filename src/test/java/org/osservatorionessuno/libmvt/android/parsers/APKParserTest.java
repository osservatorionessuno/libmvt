package org.osservatorionessuno.libmvt.android.parsers;

import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.*;

public class APKParserTest {

    @Test
    public void testExtractFileName() {
        assertEquals("_com.example.example-TxchF6T5oGfRGbrEFHW00Q", APKParser.extractFileName("/data/app/~~rQxtmhkNujoXZ5j8uDjXuA==/com.example.example-TxchF6T5oGfRGbrEFHW00Q==/base.apk"));
        assertEquals("", APKParser.extractFileName("/data/app/com.example/base.apk"));
        assertEquals("", APKParser.extractFileName("base.apk"));
    }

    @Test
    public void testParseApkMissingManifestThrows() throws Exception {
        File apk = createTempApkZip(builder -> {
            builder.add("assets/some_asset.txt", "hello");
            builder.add("lib/arm64-v8a/libfoo.so", "bin");
        });

        assertThrows(Exception.class, () -> APKParser.parseAPK(apk));
    }

    @Test
    public void testParseApkTextManifestThrows() throws Exception {
        File apk = createTempApkZip(builder -> {
            // APKParser expects a binary AndroidManifest.xml; a plaintext manifest should fail.
            builder.add("AndroidManifest.xml", "<manifest package=\"com.example\"/>");
            builder.add("assets/some_asset.txt", "hello");
        });

        assertThrows(Exception.class, () -> APKParser.parseAPK(apk));
    }

    private interface ZipBuilderAction {
        void build(ZipBuilder builder) throws Exception;
    }

    private static final class ZipBuilder {
        private final ZipOutputStream zout;

        private ZipBuilder(ZipOutputStream zout) {
            this.zout = zout;
        }

        public void add(String name, String content) throws Exception {
            ZipEntry e = new ZipEntry(name);
            zout.putNextEntry(e);
            byte[] bytes = content.getBytes(StandardCharsets.UTF_8);
            zout.write(bytes);
            zout.closeEntry();
        }
    }

    private static File createTempApkZip(ZipBuilderAction action) throws Exception {
        File f = Files.createTempFile("mvt-test-", ".apk").toFile();
        f.deleteOnExit();

        try (ZipOutputStream zout = new ZipOutputStream(new FileOutputStream(f))) {
            action.build(new ZipBuilder(zout));
        }

        return f;
    }
}

