package org.osservatorionessuno.libmvt.android.parsers;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;
import org.osservatorionessuno.libmvt.common.Utils;

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

    @Test
    public void testParseApkFromInputStreamMissingManifestThrows() throws Exception {
        File apk = createTempApkZip(builder -> {
            builder.add("assets/some_asset.txt", "hello");
            builder.add("lib/arm64-v8a/libfoo.so", "bin");
        });

        assertThrows(Exception.class, () -> APKParser.parseAPK(Files.newInputStream(apk.toPath())));
    }

    @Test
    public void testParseSignedApkFromFileAndStreamAgree() throws Exception {
        File apk = ResourcesUtils.readResourceFile("apks/signed_test.apk");

        APKParser.APKInfo fromFile = APKParser.parseAPK(apk);
        APKParser.APKInfo fromStream =
                APKParser.parseAPK(Files.newInputStream(apk.toPath()));

        assertFalse(fromFile.getPackageName().isEmpty());
        assertEquals(fromFile.getPackageName(), fromStream.getPackageName());
        assertEquals(fromFile.getVersionCode(), fromStream.getVersionCode());
        assertEquals(fromFile.getVersionName(), fromStream.getVersionName());
        assertEquals(fromFile.getSuspicious(), fromStream.getSuspicious());
        assertEquals(fromFile.getCertificates().size(), fromStream.getCertificates().size());
        assertFalse(fromFile.getCertificates().isEmpty());
        assertEquals(
                fromFile.getCertificates().get(0).getChecksums().getSha1(),
                fromStream.getCertificates().get(0).getChecksums().getSha1());
    }

    @Test
    public void testParseSignedApkUntrustedRunsStaticAnalysisPath() throws Exception {
        File apk = ResourcesUtils.readResourceFile("apks/signed_test.apk");
        APKParser.APKInfo info = APKParser.parseAPK(apk);

        assertFalse(info.getCertificates().isEmpty());
        // Test keystore is not in Utils.VALID_CERTIFICATES, so static analysis still runs.
        assertFalse(info.getCertificates().get(0).getTrusted());
        // signed_test.apk has a minimal/benign manifest → not flagged suspicious.
        assertFalse(info.getSuspicious());
    }

    @Test
    public void testParseSignedApkTrustedSkipsStaticAnalysis() throws Exception {
        File apk = ResourcesUtils.readResourceFile("apks/signed_test.apk");
        APKParser.APKInfo baseline = APKParser.parseAPK(apk);
        String sha1 = baseline.getCertificates().get(0).getChecksums().getSha1();
        assertFalse(baseline.getCertificates().get(0).getTrusted());

        Utils.VALID_CERTIFICATES.add(sha1);
        try {
            APKParser.APKInfo trusted = APKParser.parseAPK(apk);
            assertTrue(trusted.getVerified());
            assertTrue(trusted.getCertificates().get(0).getTrusted());
            // Trusted signer → no static analysis; suspicious stays false.
            assertFalse(trusted.getSuspicious());
        } finally {
            Utils.VALID_CERTIFICATES.remove(sha1);
        }
    }

    @Test
    public void testRepackagedApkDoesNotSkipStaticAnalysis() throws Exception {
        File apk = ResourcesUtils.readResourceFile("apks/signed_test.apk");
        File repackaged = ApkTamperUtils.repackageWithTamperedEntryToFile(apk, "resources.arsc");

        String sha1 = APKParser.parseAPK(apk).getCertificates().get(0).getChecksums().getSha1();

        // Allowlist the signer, as if the repackaged app carried a vendor certificate.
        Utils.VALID_CERTIFICATES.add(sha1);
        try {
            APKParser.APKInfo info = APKParser.parseAPK(repackaged);

            // Signature broken, so no certificate is trusted and the static analysis gate stays
            // open. The fixture manifest is benign, so suspicious itself cannot witness that.
            assertFalse(info.getVerified());
            assertFalse(info.getCertificates().isEmpty());
            assertTrue(info.getCertificates().stream().noneMatch(
                    CertificateParser.CertificateInfo::getTrusted));

            APKParser.APKInfo fromStream =
                    APKParser.parseAPK(Files.newInputStream(repackaged.toPath()));
            assertFalse(fromStream.getVerified());
            assertTrue(fromStream.getCertificates().stream().noneMatch(
                    CertificateParser.CertificateInfo::getTrusted));
        } finally {
            Utils.VALID_CERTIFICATES.remove(sha1);
        }
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
