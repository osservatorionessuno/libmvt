package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;
import org.osservatorionessuno.libmvt.common.Indicators;
import org.osservatorionessuno.libmvt.common.JvmMapStringResolver;
import org.osservatorionessuno.libmvt.common.AlertLevel;
import org.osservatorionessuno.libmvt.common.Detection;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class PackagesTest {

    private static Packages parseAndroidQfPackages() throws Exception {
        Packages p = new Packages();
        p.setStringResolver(new JvmMapStringResolver());
        try (InputStream data = ResourcesUtils.readResource("androidqf/packages.json")) {
            p.parse(data);
        }
        return p;
    }

    private static boolean anyDetectionContextContains(List<Detection> detections, String needle, AlertLevel level) {
        if (detections == null) return false;
        for (Detection d : detections) {
            if (d.getLevel().equals(level) && d.getContext().contains(needle)) return true;
        }
        return false;
    }

    private static Indicators indicatorsFromJson(String json) throws Exception {
        Path dir = Files.createTempDirectory("mvt-iocs-");
        Files.writeString(dir.resolve("iocs.json"), json, StandardCharsets.UTF_8);
        Indicators indicators = new Indicators();
        indicators.loadFromDirectory(dir.toFile());
        return indicators;
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

        assertTrue(anyDetectionContextContains(p.detected, "com.whatsapp", AlertLevel.HIGH));
        assertTrue(anyDetectionContextContains(p.detected, "app.revanced.manager.flutter", AlertLevel.MEDIUM));
        assertTrue(anyDetectionContextContains(p.detected, "org.nuclearfog.apollo", AlertLevel.INFO));
        assertTrue(anyDetectionContextContains(p.detected, "installer=\\\"com.google.android.packageinstaller\\\"", AlertLevel.MEDIUM));
        assertTrue(anyDetectionContextContains(p.detected, "installer=\\\"org.fdroid.fdroid\\\"", AlertLevel.INFO));
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

        assertTrue(anyDetectionContextContains(p.detected, "APP_ID", AlertLevel.CRITICAL));
        assertTrue(anyDetectionContextContains(p.detected, "com.malware.blah", AlertLevel.CRITICAL));
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

        assertTrue(anyDetectionContextContains(p.detected, "FILE_HASH_SHA256", AlertLevel.CRITICAL));
        assertTrue(anyDetectionContextContains(p.detected, sha256, AlertLevel.CRITICAL));
        
        // TODO: Detection result does not contain the package name.
        //assertTrue(anyDetectionContextContains(p.detected, "com.malware.muahaha", AlertLevel.CRITICAL));
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

        assertTrue(anyDetectionContextContains(p.detected, "APP_CERT_HASH_SHA256", AlertLevel.CRITICAL));
        assertTrue(anyDetectionContextContains(p.detected, certSha256, AlertLevel.CRITICAL));
        
        // TODO: Detection result does not contain the package name.
        //assertTrue(anyDetectionContextContains(p.detected, "com.malware.muahaha", AlertLevel.CRITICAL));
    }
}
