package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;
import org.osservatorionessuno.libmvt.common.AlertLevel;
import org.osservatorionessuno.libmvt.common.DetectionType;
import org.osservatorionessuno.libmvt.common.Indicators;

import java.io.InputStream;
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

    private static Packages withIndicators(String path, Indicators indicators) throws Exception {
        return parse(path, indicators, null);
    }

    @Test
    public void testPackagesList() throws Exception {
        List<Object> sink = new ArrayList<>();
        Packages p = parse("packages.json", null, sink);
        assertEquals(7, sink.size());
        assertEquals(7, p.getRecordCount());
    }

    @Test
    public void testPackagesListJsonl() throws Exception {
        List<Object> sink = new ArrayList<>();
        Packages p = parse("packages.jsonl", null, sink);
        assertEquals(7, sink.size());
        assertEquals(7, p.getRecordCount());
    }

    /** The .jsonl parser yields the same detections as the .json parser for the same fixture. */
    @Test
    public void testJsonlDetectionsMatchJson() throws Exception {
        Packages fromJson = parse("packages.json", null, null);
        Packages fromJsonl = parse("packages.jsonl", null, null);
        assertEquals(fromJson.detected, fromJsonl.detected);
        assertEquals(5, fromJsonl.detected.size());
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

}
