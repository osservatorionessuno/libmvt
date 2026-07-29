package org.osservatorionessuno.libmvt.android.parsers;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;
import org.osservatorionessuno.libmvt.common.Utils;

import java.io.File;
import java.nio.file.Files;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class SignatureParserTest {

    @Test
    public void testParseAPKSignatureFromFile() throws Exception {
        File apk = ResourcesUtils.readResourceFile("apks/signed_test.apk");
        SignatureParser.APKSignatureInfo info = new SignatureParser().parseAPKSignature(apk);

        assertTrue(info.getVerified());
        assertFalse(info.getSignerCertificates().isEmpty());
        assertEquals(
                "C=Unknown,ST=Unknown,L=Unknown,O=LibMVT,OU=LibMVT,CN=Test",
                info.getSignerCertificates().get(0).getSubject());
        assertFalse(info.getSignerCertificates().get(0).getTrusted());
    }

    @Test
    public void testParseAPKSignatureFromBytesMatchesFile() throws Exception {
        File apk = ResourcesUtils.readResourceFile("apks/signed_test.apk");
        byte[] bytes = Files.readAllBytes(apk.toPath());

        SignatureParser parser = new SignatureParser();
        SignatureParser.APKSignatureInfo fromFile = parser.parseAPKSignature(apk);
        SignatureParser.APKSignatureInfo fromBytes = parser.parseAPKSignature(bytes);

        assertEquals(fromFile.getVerified(), fromBytes.getVerified());
        assertEquals(
                fromFile.getVerifiedUsingV1Scheme(),
                fromBytes.getVerifiedUsingV1Scheme());
        assertEquals(
                fromFile.getVerifiedUsingV2Scheme(),
                fromBytes.getVerifiedUsingV2Scheme());
        assertEquals(
                fromFile.getVerifiedUsingV3Scheme(),
                fromBytes.getVerifiedUsingV3Scheme());

        List<CertificateParser.CertificateInfo> fileCerts = fromFile.getSignerCertificates();
        List<CertificateParser.CertificateInfo> byteCerts = fromBytes.getSignerCertificates();
        assertEquals(fileCerts.size(), byteCerts.size());
        assertEquals(fileCerts.get(0).getSubject(), byteCerts.get(0).getSubject());
        assertEquals(
                fileCerts.get(0).getChecksums().getSha1(),
                byteCerts.get(0).getChecksums().getSha1());
        assertEquals(fileCerts.get(0).getTrusted(), byteCerts.get(0).getTrusted());
    }

    @Test
    public void testRepackagedApkIsNotTrustedEvenWhenAllowlisted() throws Exception {
        File apk = ResourcesUtils.readResourceFile("apks/tampered_test.apk");
        byte[] repackaged = Files.readAllBytes(apk.toPath());

        SignatureParser.APKSignatureInfo info =
                new SignatureParser().parseAPKSignature(repackaged);

        // The certificate survives repackaging, so it is still reported...
        assertFalse(info.getVerified());
        assertFalse(info.getSignerCertificates().isEmpty());
        String sha1 = info.getSignerCertificates().get(0).getChecksums().getSha1();

        // ...but an allowlisted fingerprint must not confer trust without a verified signature:
        // anyone can copy a vendor certificate into an APK they repackaged.
        Utils.VALID_CERTIFICATES.add(sha1);
        try {
            SignatureParser.APKSignatureInfo allowlisted =
                    new SignatureParser().parseAPKSignature(repackaged);
            assertFalse(allowlisted.getVerified());
            assertTrue(allowlisted.getSignerCertificates().stream().noneMatch(
                    CertificateParser.CertificateInfo::getTrusted));
        } finally {
            Utils.VALID_CERTIFICATES.remove(sha1);
        }
    }

    @Test
    public void testParseAPKSignatureFromBytesOnUnsignedThrows() throws Exception {
        File apk = ResourcesUtils.readResourceFile("apks/unsigned_test.apk");
        byte[] bytes = Files.readAllBytes(apk.toPath());

        assertThrows(
                SignatureParser.SignatureParsingException.class,
                () -> new SignatureParser().parseAPKSignature(bytes));
    }
}
