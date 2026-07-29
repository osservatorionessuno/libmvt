package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;
import org.osservatorionessuno.libmvt.common.AlertLevel;
import org.osservatorionessuno.libmvt.common.DetectionType;
import org.osservatorionessuno.libmvt.common.Indicators;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetection;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionValueContains;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.streamArtifact;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.streamRecords;

public class FilesTest {

    private static List<Object> records(String path, InputStream data) throws Exception {
        return streamRecords(Files::new, path, data);
    }

    /**
     * Parses from a FileInputStream, as ForensicRunner does. ByteArrayInputStream.close()
     * is a no-op, so it hides read-after-close bugs that abort a real scan.
     */
    private static List<Object> recordsFromFile(String content) throws Exception {
        Path file = java.nio.file.Files
                .createTempDirectory("mvt-files-json-")
                .resolve("files.json");
        java.nio.file.Files.writeString(file, content, StandardCharsets.UTF_8);
        try (InputStream in = new FileInputStream(file.toFile())) {
            return records("files.json", in);
        }
    }

    private static InputStream json(String s) {
        return new ByteArrayInputStream(s.getBytes(StandardCharsets.UTF_8));
    }

    private static Indicators indicators(String body) throws Exception {
        Path dir = java.nio.file.Files.createTempDirectory("mvt-files-iocs-");
        java.nio.file.Files.writeString(dir.resolve("iocs.json"), body, StandardCharsets.UTF_8);
        Indicators indicators = new Indicators();
        indicators.loadFromDirectory(dir.toFile());
        return indicators;
    }

    @Test
    public void testParsingJson() throws Exception {
        List<Object> parsed = records("files.json", ResourcesUtils.readResource("androidqf/files.json"));
        assertEquals(3, parsed.size());

        @SuppressWarnings("unchecked")
        Map<String, Object> first = (Map<String, Object>) parsed.get(0);
        assertEquals("/sdcard/.profig.os", first.get("path"));
    }

    @Test
    public void testParsingProtobuf() throws Exception {
        List<Object> parsed = records("files.pb", ResourcesUtils.readResource("androidqf/files.pb"));
        assertEquals(3, parsed.size());

        @SuppressWarnings("unchecked")
        Map<String, Object> first = (Map<String, Object>) parsed.get(0);
        assertEquals("/sdcard/.profig.os", first.get("path"));
        assertEquals(1593109532.0, first.get("mtime"));
        assertEquals("-rw-rw----", first.get("mode"));
        assertEquals(36L, first.get("size"));
    }

    /** Records are observed as they stream, and nothing is retained beyond the count. */
    @Test
    public void testRecordsAreNotRetained() throws Exception {
        List<Object> sink = new ArrayList<>();
        Files files = streamArtifact(
                Files::new, "files.pb", ResourcesUtils.readResource("androidqf/files.pb"), null, sink);

        assertEquals(3, sink.size());
        assertEquals(3, files.getRecordCount());
    }

    @Test
    public void testParsingJsonLines() throws Exception {
        List<Object> parsed = recordsFromFile("""
                {"path":"/data/local/tmp/a"}
                {"path":"/data/local/tmp/b"}
                """);
        assertEquals(2, parsed.size());

        @SuppressWarnings("unchecked")
        Map<String, Object> first = (Map<String, Object>) parsed.get(0);
        assertEquals("/data/local/tmp/a", first.get("path"));
    }

    @Test
    public void testMalformedJsonIsSkippedNotFatal() throws Exception {
        assertEquals(0, recordsFromFile("").size());
        assertEquals(0, recordsFromFile("   \n").size());
        assertEquals(0, recordsFromFile("[{\"path\":\"/data/local/tmp/a\"}").size());
    }

    /** The suspicious-path heuristic needs no indicators. */
    @Test
    public void testSuspiciousExecutablePath() throws Exception {
        Files files = streamArtifact(
                Files::new,
                "files.json",
                json("[{\"path\":\"/data/local/tmp/evil\",\"mode\":\"-rwxr-xr-x\",\"size\":123}]"));

        assertEquals(1, files.detected.size());
        assertDetection(files.detected, DetectionType.FILES_SUSPICIOUS_PATH, AlertLevel.HIGH);
        assertDetectionValueContains(files.detected, DetectionType.FILES_SUSPICIOUS_PATH, "/data/local/tmp/evil");
    }

    /**
     * The executable marker has to survive both mode encodings: find -printf '%m' gives octal
     * digits, androidqf's collector gives a symbolic string.
     */
    @Test
    public void testExecutableMarkerAcrossModeEncodings() throws Exception {
        assertEquals("executable ", fileTypeFor("\"755\""));
        assertEquals("executable ", fileTypeFor("\"0755\""));
        assertEquals("executable ", fileTypeFor("\"-rwxr-xr-x\""));
        assertEquals("executable ", fileTypeFor("\"-rwsr-xr-x\""));
        assertEquals("executable ", fileTypeFor("\"rwxr-xr-x\""));
        assertEquals("executable ", fileTypeFor("493"));

        assertEquals("", fileTypeFor("\"644\""));
        assertEquals("", fileTypeFor("\"-rw-r--r--\""));
        assertEquals("", fileTypeFor("\"-rw-rw----\""));
        // uppercase S is setuid without execute
        assertEquals("", fileTypeFor("\"-rwSr--r--\""));
        assertEquals("", fileTypeFor("null"));
        assertEquals("", fileTypeFor("\"\""));
    }

    /** Second value of the FILES_SUSPICIOUS_PATH detection for a given JSON mode literal. */
    private static String fileTypeFor(String modeJson) throws Exception {
        Files files = streamArtifact(
                Files::new,
                "files.json",
                json("[{\"path\":\"/data/local/tmp/x\",\"mode\":" + modeJson + "}]"));

        assertEquals(1, files.detected.size(), "mode=" + modeJson);
        return files.detected.get(0).getValue().get(1);
    }

    @Test
    public void testIocFileHash() throws Exception {
        String sha256 = "87e7e7a28ab69fbc377f60ba5c5640d31735cf8eb9af4de35f78b40e0e2970b1";
        Indicators indicators = indicators(
                "{ \"indicators\": [ { \"file:hashes.sha256\": [ \"" + sha256 + "\" ] } ] }");

        Files files = streamArtifact(
                Files::new,
                "files.json",
                json(String.format("[{\"path\":\"/system/app/sample\",\"sha256\":\"%s\"}]", sha256)),
                indicators);

        assertEquals(1, files.detected.size());
        assertDetection(files.detected, DetectionType.IOC_MATCH, AlertLevel.CRITICAL);
        assertDetectionValueContains(files.detected, DetectionType.IOC_MATCH, sha256);
    }
}
