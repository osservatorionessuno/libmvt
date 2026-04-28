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
        System.out.println(cert.getSubjectX500Principal().getName());

        CertificateParser.CertificateInfo info = CertificateParser.fromX509Certificate(cert);
        System.out.println(info.getSubject());

        assertNotNull(info);
        assertNotNull(info.getSubject());
        assertEquals("C=Unknown,ST=Unknown,L=Unknown,O=LibMVT,OU=LibMVT,CN=Test", info.getSubject());
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
