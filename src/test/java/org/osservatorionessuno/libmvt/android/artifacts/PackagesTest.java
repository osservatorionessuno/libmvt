package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;
import org.osservatorionessuno.libmvt.common.AbstractInput;
import org.osservatorionessuno.libmvt.common.AlertLevel;
import org.osservatorionessuno.libmvt.common.DetectionType;
import org.osservatorionessuno.libmvt.common.Indicators;
import org.osservatorionessuno.libmvt.common.JvmMapStringResolver;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionValue;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionValueContains;

public class PackagesTest {

    private static Packages parse(String path, InputStream data) throws Exception {
        Packages p = new Packages();
        p.setStringResolver(new JvmMapStringResolver());
        p.parse(new AbstractInput(path, data) {});
        return p;
    }

    private static Packages parseAndroidQfPackages() throws Exception {
        try (InputStream data = ResourcesUtils.readResource("androidqf/packages.json")) {
            return parse("packages.json", data);
        }
    }

    private static Indicators indicatorsFromJson(String json) throws Exception {
        Path dir = Files.createTempDirectory("mvt-iocs-");
        Files.writeString(dir.resolve("iocs.json"), json, StandardCharsets.UTF_8);
        Indicators indicators = new Indicators();
        indicators.loadFromDirectory(dir.toFile());
        return indicators;
    }

    @Test
    public void testParsingProtobuf() throws Exception {
        Packages p;
        try (InputStream data = ResourcesUtils.readResource("androidqf/packages.pb")) {
            p = parse("packages.pb", data);
        }
        assertEquals(7, p.getResults().size());
        assertTrue(p.getResults().get(0).toString().contains("name=com.whatsapp"));
        assertTrue(p.getResults().get(0).toString().contains(
                "744ed47f8176ec423840344c33e88bd2c96e8988cda0797f3415bb5229efc12b"));
    }

    @Test
    public void testPackagesList() throws Exception {
        Packages p = parseAndroidQfPackages();
        assertEquals(7, p.getResults().size());
        assertTrue(p.detected.isEmpty());
    }

    @Test
    public void testNonAppstoreWarnings() throws Exception {
        Packages p = parseAndroidQfPackages();
        p.checkIndicators();

        // Matches the AndroidQF fixture: whatsapp (null installer), revanced + fdroid (browser installer),
        // apollo (third party store installer).

        assertEquals(5, p.detected.size());

        assertDetectionValueContains(p.detected, DetectionType.PACKAGES_ADB_INSTALLED, "com.whatsapp");
        assertDetectionValueContains(p.detected, DetectionType.PACKAGES_BROWSER_INSTALLED, "app.revanced.manager.flutter");
        assertDetectionValueContains(p.detected, DetectionType.PACKAGES_THIRD_PARTY_STORE_INSTALLED, "org.nuclearfog.apollo");
        assertDetectionValueContains(p.detected, DetectionType.PACKAGES_BROWSER_INSTALLED, "com.google.android.packageinstaller");
        assertDetectionValueContains(p.detected, DetectionType.PACKAGES_BROWSER_INSTALLED, "org.fdroid.fdroid");
    }

    @Test
    public void testPackagesIocPackageNames() throws Exception {
        Packages p = parseAndroidQfPackages();

        // APP_ID IOC for package name.
        Indicators indicators = indicatorsFromJson(
                "{ \"indicators\": [ { \"app:id\": [ \"com.malware.blah\" ] } ] }"
        );
        p.setIndicators(indicators);
        p.checkIndicators();

        assertDetectionValueContains(p.detected, DetectionType.IOC_MATCH, AlertLevel.CRITICAL, "APP_ID");
        assertDetectionValueContains(p.detected, DetectionType.IOC_MATCH, AlertLevel.CRITICAL, "com.malware.blah");
    }

    @Test
    public void testPackagesIocSha256() throws Exception {
        Packages p = parseAndroidQfPackages();

        // SHA256 IOC for a package file.
        String sha256 = "31037a27af59d4914906c01ad14a318eee2f3e31d48da8954dca62a99174e3fa";
        Indicators indicators = indicatorsFromJson(
                "{ \"indicators\": [ { \"file:hashes.sha256\": [ \"" + sha256 + "\" ] } ] }"
        );
        p.setIndicators(indicators);
        p.checkIndicators();

        assertDetectionValueContains(p.detected, DetectionType.IOC_MATCH, AlertLevel.CRITICAL, "FILE_HASH_SHA256");
        assertDetectionValueContains(p.detected, DetectionType.IOC_MATCH, AlertLevel.CRITICAL, sha256);
        assertDetectionValueContains(p.detected, DetectionType.IOC_MATCH, AlertLevel.CRITICAL, "com.malware.muahaha");
        assertDetectionValue(
                p.detected,
                DetectionType.IOC_MATCH,
                List.of("FILE_HASH_SHA256", sha256, "com.malware.muahaha"));
    }

    @Test
    public void testPackagesCertificateHashIoc() throws Exception {
        Packages p = parseAndroidQfPackages();

        // Certificate SHA256 IOC for a package file certificate.
        String certSha256 = "c7e56178748be1441370416d4c10e34817ea0c961eb636c8e9d98e0fd79bf730";
        Indicators indicators = indicatorsFromJson(
                "{ \"indicators\": [ { \"app:cert.sha256\": [ \"" + certSha256 + "\" ] } ] }"
        );
        p.setIndicators(indicators);
        p.checkIndicators();

        assertDetectionValueContains(p.detected, DetectionType.IOC_MATCH, AlertLevel.CRITICAL, "APP_CERT_HASH_SHA256");
        assertDetectionValueContains(p.detected, DetectionType.IOC_MATCH, AlertLevel.CRITICAL, certSha256);
        assertDetectionValueContains(p.detected, DetectionType.IOC_MATCH, AlertLevel.CRITICAL, "com.malware.muahaha");
        assertDetectionValue(
                p.detected,
                DetectionType.IOC_MATCH,
                List.of("APP_CERT_HASH_SHA256", certSha256, "com.malware.muahaha"));
    }
}
