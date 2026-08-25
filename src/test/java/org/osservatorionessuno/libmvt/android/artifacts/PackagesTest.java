package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;
import org.osservatorionessuno.libmvt.common.AlertLevel;
import org.osservatorionessuno.libmvt.common.DetectionType;
import org.osservatorionessuno.libmvt.common.Indicators;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionValue;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionValueContains;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.indicatorsFromJson;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.streamArtifact;

public class PackagesTest {

    private static Packages parse(String path, Indicators indicators, List<Object> sink)
            throws Exception {
        try (InputStream data = ResourcesUtils.readResource("androidqf/" + path)) {
            return streamArtifact(Packages::new, path, data, indicators, sink);
        }
    }

    private static List<Object> records(String path) throws Exception {
        List<Object> sink = new ArrayList<>();
        parse(path, null, sink);
        return sink;
    }

    private static Packages withIndicators(String path, Indicators indicators) throws Exception {
        return parse(path, indicators, null);
    }

    @Test
    public void testParsingProtobuf() throws Exception {
        List<Object> parsed = records("packages.pb");
        assertEquals(7, parsed.size());
        assertTrue(parsed.get(0).toString().contains("name=com.whatsapp"));
        assertTrue(parsed.get(0).toString().contains(
                "744ed47f8176ec423840344c33e88bd2c96e8988cda0797f3415bb5229efc12b"));
    }

    @Test
    public void testPackagesList() throws Exception {
        List<Object> sink = new ArrayList<>();
        Packages p = parse("packages.json", null, sink);
        assertEquals(7, sink.size());
        assertEquals(7, p.getRecordCount());
    }

    @Test
    public void testNonAppstoreWarnings() throws Exception {
        // Matches the AndroidQF fixture: whatsapp (null installer), revanced + fdroid (browser
        // installer), apollo (third party store installer). Needs no indicators.
        Packages p = parse("packages.json", null, null);

        assertEquals(5, p.detected.size());

        assertDetectionValueContains(p.detected, DetectionType.PACKAGES_ADB_INSTALLED, "com.whatsapp");
        assertDetectionValueContains(p.detected, DetectionType.PACKAGES_BROWSER_INSTALLED, "app.revanced.manager.flutter");
        assertDetectionValueContains(p.detected, DetectionType.PACKAGES_THIRD_PARTY_STORE_INSTALLED, "org.nuclearfog.apollo");
        assertDetectionValueContains(p.detected, DetectionType.PACKAGES_BROWSER_INSTALLED, "com.google.android.packageinstaller");
        assertDetectionValueContains(p.detected, DetectionType.PACKAGES_BROWSER_INSTALLED, "org.fdroid.fdroid");
    }

    @Test
    public void testPackagesIocPackageNames() throws Exception {
        // APP_ID IOC for package name.
        Packages p = withIndicators("packages.json", indicatorsFromJson(
                "{ \"indicators\": [ { \"app:id\": [ \"com.malware.blah\" ] } ] }"));

        assertDetectionValueContains(p.detected, DetectionType.IOC_MATCH, AlertLevel.CRITICAL, "APP_ID");
        assertDetectionValueContains(p.detected, DetectionType.IOC_MATCH, AlertLevel.CRITICAL, "com.malware.blah");
    }

    @Test
    public void testPackagesIocSha256() throws Exception {
        // SHA256 IOC for a package file.
        String sha256 = "31037a27af59d4914906c01ad14a318eee2f3e31d48da8954dca62a99174e3fa";
        Packages p = withIndicators("packages.json", indicatorsFromJson(
                "{ \"indicators\": [ { \"file:hashes.sha256\": [ \"" + sha256 + "\" ] } ] }"));

        assertDetectionValue(
                p.detected,
                DetectionType.IOC_MATCH,
                List.of("", "FILE_HASH_SHA256", sha256, "com.malware.muahaha"));
    }

    @Test
    public void testPackagesCertificateHashIoc() throws Exception {
        // Certificate SHA256 IOC for a package file certificate.
        String certSha256 = "c7e56178748be1441370416d4c10e34817ea0c961eb636c8e9d98e0fd79bf730";
        Packages p = withIndicators("packages.json", indicatorsFromJson(
                "{ \"indicators\": [ { \"app:cert.sha256\": [ \"" + certSha256 + "\" ] } ] }"));

        assertDetectionValue(
                p.detected,
                DetectionType.IOC_MATCH,
                List.of("", "APP_CERT_HASH_SHA256", certSha256, "com.malware.muahaha"));
    }

    private static void varint(ByteArrayOutputStream o, int v) {
        while (true) {
            if ((v & ~0x7F) == 0) { o.write(v); return; }
            o.write((v & 0x7F) | 0x80);
            v >>>= 7;
        }
    }

    private static byte[] lengthDelimited(int field, byte[] payload) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        varint(o, (field << 3) | 2);
        varint(o, payload.length);
        o.writeBytes(payload);
        return o.toByteArray();
    }

    private static byte[] str(int field, String value) {
        return lengthDelimited(field, value.getBytes(StandardCharsets.UTF_8));
    }

    /** One package, one APK, field 8 repeated: signed by two different certificates. */
    private static byte[] multiSignerPackagesPb(String certA, String certB) {
        ByteArrayOutputStream file = new ByteArrayOutputStream();
        file.writeBytes(str(1, "/data/app/com.multi.signer/base.apk"));
        file.writeBytes(lengthDelimited(8, str(3, certA)));
        file.writeBytes(lengthDelimited(8, str(3, certB)));

        ByteArrayOutputStream pkg = new ByteArrayOutputStream();
        pkg.writeBytes(str(1, "com.multi.signer"));
        pkg.writeBytes(lengthDelimited(7, file.toByteArray()));

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        varint(out, pkg.size());
        out.writeBytes(pkg.toByteArray());
        return out.toByteArray();
    }

    /**
     * APKs in the wild carry several signing certificates and SignatureParser keeps them all,
     * so every one has to be matched. An IOC is placed on each, since a parser that kept only
     * the last would still match certB.
     */
    @Test
    public void testAllSignerCertificatesAreMatchedFromProtobuf() throws Exception {
        String certA = "1111111111111111111111111111111111111111111111111111111111111111";
        String certB = "2222222222222222222222222222222222222222222222222222222222222222";
        Indicators indicators = indicatorsFromJson(
                "{ \"indicators\": [ { \"app:cert.sha256\": [ \""
                        + certA + "\", \"" + certB + "\" ] } ] }");

        Packages p = streamArtifact(
                Packages::new,
                "packages.pb",
                new ByteArrayInputStream(multiSignerPackagesPb(certA, certB)),
                indicators);

        assertDetectionValue(
                p.detected,
                DetectionType.IOC_MATCH,
                List.of("", "APP_CERT_HASH_SHA256", certA, "com.multi.signer"));
        assertDetectionValueContains(p.detected, DetectionType.IOC_MATCH, certB);
    }

    @Test
    public void testPackagesCertificateHashIocFromProtobuf() throws Exception {
        // Certificate SHA256 IOC, protobuf encoding.
        String certSha256 = "c7e56178748be1441370416d4c10e34817ea0c961eb636c8e9d98e0fd79bf730";
        Packages p = withIndicators("packages.pb", indicatorsFromJson(
                "{ \"indicators\": [ { \"app:cert.sha256\": [ \"" + certSha256 + "\" ] } ] }"));

        assertDetectionValue(
                p.detected,
                DetectionType.IOC_MATCH,
                List.of("", "APP_CERT_HASH_SHA256", certSha256, "com.malware.muahaha"));
    }
}
