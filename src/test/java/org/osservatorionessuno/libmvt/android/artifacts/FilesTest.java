package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;
import org.osservatorionessuno.libmvt.common.AlertLevel;
import org.osservatorionessuno.libmvt.common.DetectionType;
import org.osservatorionessuno.libmvt.common.Indicators;
import org.osservatorionessuno.libmvt.android.artifacts.Files;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetection;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionValueContains;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.parseAndroidArtifact;

public class FilesTest {

    @Test
    public void testParsingJson() throws Exception {
        Files files = parseAndroidArtifact(
                Files::new,
                "files.json",
                ResourcesUtils.readResource("androidqf/files.json"));
        assertEquals(3, files.getResults().size());

        @SuppressWarnings("unchecked")
        Map<String, Object> first = (Map<String, Object>) files.getResults().get(0);
        assertEquals("/sdcard/.profig.os", first.get("path"));
    }

    @Test
    public void testParsingProtobuf() throws Exception {
        Files files = parseAndroidArtifact(
                Files::new,
                "files.pb",
                ResourcesUtils.readResource("androidqf/files.pb"));
        assertEquals(3, files.getResults().size());

        @SuppressWarnings("unchecked")
        Map<String, Object> first = (Map<String, Object>) files.getResults().get(0);
        assertEquals("/sdcard/.profig.os", first.get("path"));
        assertEquals(1593109532.0, first.get("mtime"));
        assertEquals("-rw-rw----", first.get("mode"));
        assertEquals(36L, first.get("size"));
    }

    private static Indicators emptyIndicators() throws Exception {
        Path dir = java.nio.file.Files.createTempDirectory("mvt-empty-iocs-");
        java.nio.file.Files.writeString(
                dir.resolve("iocs.json"),
                "{ \"indicators\": [] }",
                StandardCharsets.UTF_8);
        Indicators indicators = new Indicators();
        indicators.loadFromDirectory(dir.toFile());
        return indicators;
    }

    @Test
    public void testSuspiciousExecutablePath() throws Exception {
        String json = """
                [{"path":"/data/local/tmp/evil","mode":"-rwxr-xr-x","size":123}]
                """;
        Files files = parseAndroidArtifact(
                Files::new,
                "files.json",
                new ByteArrayInputStream(json.getBytes(StandardCharsets.UTF_8)));
        files.setIndicators(emptyIndicators());
        files.checkIndicators();

        assertEquals(1, files.detected.size());
        assertDetection(files.detected, DetectionType.FILES_SUSPICIOUS_PATH, AlertLevel.HIGH);
        assertDetectionValueContains(files.detected, DetectionType.FILES_SUSPICIOUS_PATH, "/data/local/tmp/evil");
    }

    @Test
    public void testIocFileHash() throws Exception {
        String sha256 = "87e7e7a28ab69fbc377f60ba5c5640d31735cf8eb9af4de35f78b40e0e2970b1";
        String json = String.format(
                "[{\"path\":\"/system/app/sample\",\"sha256\":\"%s\"}]",
                sha256);
        Files files = parseAndroidArtifact(
                Files::new,
                "files.json",
                new ByteArrayInputStream(json.getBytes(StandardCharsets.UTF_8)));

        Path dir = java.nio.file.Files.createTempDirectory("mvt-files-iocs-");
        java.nio.file.Files.writeString(
                dir.resolve("iocs.json"),
                "{ \"indicators\": [ { \"file:hashes.sha256\": [ \"" + sha256 + "\" ] } ] }",
                StandardCharsets.UTF_8);
        Indicators indicators = new Indicators();
        indicators.loadFromDirectory(dir.toFile());
        files.setIndicators(indicators);
        files.checkIndicators();

        assertEquals(1, files.detected.size());
        assertDetection(files.detected, DetectionType.IOC_MATCH, AlertLevel.CRITICAL);
        assertDetectionValueContains(files.detected, DetectionType.IOC_MATCH, sha256);
    }
}
