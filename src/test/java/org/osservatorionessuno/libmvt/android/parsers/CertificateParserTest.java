package org.osservatorionessuno.libmvt.android.parsers;

import org.junit.jupiter.api.Test;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.io.File;
import java.nio.file.Files;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import com.android.apksig.ApkVerifier;
import org.osservatorionessuno.libmvt.ResourcesUtils;
import org.osservatorionessuno.libmvt.common.Utils;

import static org.junit.jupiter.api.Assertions.*;

public class CertificateParserTest {

    @Test
    public void testFormatPrincipalMapsEmailOidToE() {
        X500Principal p = new X500Principal("1.2.840.113549.1.9.1=test@example.com,CN=Test");
        String formatted = CertificateParser.formatPrincipal(p);
        assertTrue(formatted.contains("E=test@example.com"));
        assertTrue(formatted.contains("CN=Test"));
    }

    @Test
    public void testFormatPrincipalReversesRdnOrder() {
        X500Principal p = new X500Principal("CN=Test,OU=LibMVT,O=LibMVT,L=Unknown,ST=Unknown,C=Unknown");
        String formatted = CertificateParser.formatPrincipal(p);
        assertEquals("C=Unknown,ST=Unknown,L=Unknown,O=LibMVT,OU=LibMVT,CN=Test", formatted);
    }

    @Test
    public void testFormatPrincipalHandlesEscapedCommaInValue() {
        X500Principal p = new X500Principal("CN=Last\\, First,C=US");
        String formatted = CertificateParser.formatPrincipal(p);
        assertEquals("C=US,CN=Last\\, First", formatted);
    }

    @Test
    public void testFormatPrincipalKeepsMultiValuedRdnTogether() {
        X500Principal p = new X500Principal("CN=Test+OU=Dev,C=US");
        String formatted = CertificateParser.formatPrincipal(p);
        assertEquals("C=US,CN=Test+OU=Dev", formatted);
    }

    @Test
    public void testParseCertificateSubjectFromApk() throws Exception {
        File apk = ResourcesUtils.readResourceFile("apks/signed_test.apk");
        ApkVerifier verifier = new ApkVerifier.Builder(apk).build();
        ApkVerifier.Result result = verifier.verify();
        
        assertEquals(0, result.getErrors().size());

        X509Certificate cert = result.getSignerCertificates().get(0);
        CertificateParser.CertificateInfo info = CertificateParser.fromX509Certificate(cert);

        assertNotNull(info);
        assertNotNull(info.getSubject());
        assertEquals("C=Unknown,ST=Unknown,L=Unknown,O=LibMVT,OU=LibMVT,CN=Test", info.getSubject());
    }

    @Test
    public void testFromX509CertificateTrustedUsesValidCertificatesAllowlist() throws Exception {
        File apk = ResourcesUtils.readResourceFile("apks/signed_test.apk");
        ApkVerifier verifier = new ApkVerifier.Builder(apk).build();
        X509Certificate cert = verifier.verify().getSignerCertificates().get(0);

        CertificateParser.CertificateInfo untrusted = CertificateParser.fromX509Certificate(cert);
        assertFalse(untrusted.getTrusted());
        assertFalse(Utils.VALID_CERTIFICATES.contains(untrusted.getChecksums().getSha1()));

        String sha1 = untrusted.getChecksums().getSha1();
        Utils.VALID_CERTIFICATES.add(sha1);
        try {
            CertificateParser.CertificateInfo trusted =
                    CertificateParser.fromX509Certificate(cert, true);
            assertTrue(trusted.getTrusted());
            assertEquals(sha1, trusted.getChecksums().getSha1());

            // Allowlisted, but nothing verified a signature made with it: not trusted.
            assertFalse(CertificateParser.fromX509Certificate(cert, false).getTrusted());
            assertFalse(CertificateParser.fromX509Certificate(cert).getTrusted());
        } finally {
            Utils.VALID_CERTIFICATES.remove(sha1);
        }

        // Allowlist mutation must not leak across tests.
        assertFalse(CertificateParser.fromX509Certificate(cert, true).getTrusted());
    }

    /**
     * Ensure we can run ApkVerifier in tests.
     * The APK we generate here is intentionally unsigned, so verification should fail.
     */
    @Test
    public void testApkVerifierRunsOnUnsignedApk() throws Exception {
        File apk = ResourcesUtils.readResourceFile("apks/unsigned_test.apk");
        ApkVerifier verifier = new ApkVerifier.Builder(apk).build();
        try {
            ApkVerifier.Result result = verifier.verify();
        } catch (Exception e) {
            System.out.println(e.getMessage());
            assertTrue(e.getMessage().contains("Failed to verify APK"));
        }
    }
}
