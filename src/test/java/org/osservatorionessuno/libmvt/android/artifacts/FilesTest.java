package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;
import org.osservatorionessuno.libmvt.common.AlertLevel;
import org.osservatorionessuno.libmvt.common.DetectionType;
import org.osservatorionessuno.libmvt.common.Indicators;
import org.osservatorionessuno.libmvt.common.JvmMapStringResolver;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.*;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetection;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionValueContains;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.parseArtifact;

public class FilesTest {

    /**
     * Files streams: every record is checked and then dropped, so getResults() stays empty.
     * Decoded records are observed through recordObserver instead, and indicators have to be
     * set before parse because there is nothing left to re-check afterwards.
     */
    private static Files parse(String path, InputStream data, List<Object> sink, Consumer<Files> configure)
            throws Exception {
        return parseArtifact(Files::new, path, data, files -> {
            files.setStringResolver(new JvmMapStringResolver());
            files.setRecordObserver(sink::add);
            configure.accept(files);
        });
    }

    private static List<Object> records(String path, InputStream data) throws Exception {
        List<Object> sink = new ArrayList<>();
        parse(path, data, sink, files -> { });
        return sink;
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

    /** Nothing is retained, whatever the artifact's size. */
    @Test
    public void testResultsAreNotRetained() throws Exception {
        List<Object> sink = new ArrayList<>();
        Files files = parse("files.pb", ResourcesUtils.readResource("androidqf/files.pb"), sink, f -> { });
        assertEquals(3, sink.size());
        assertTrue(files.getResults().isEmpty());
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
        List<Object> sink = new ArrayList<>();
        Files files = parse(
                "files.json",
                json("[{\"path\":\"/data/local/tmp/evil\",\"mode\":\"-rwxr-xr-x\",\"size\":123}]"),
                sink,
                f -> { });

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
        List<Object> sink = new ArrayList<>();
        Files files = parse(
                "files.json",
                json("[{\"path\":\"/data/local/tmp/x\",\"mode\":" + modeJson + "}]"),
                sink,
                f -> { });
        assertEquals(1, files.detected.size(), "mode=" + modeJson);
        return files.detected.get(0).getValue().get(1);
    }

    @Test
    public void testIocFileHash() throws Exception {
        String sha256 = "87e7e7a28ab69fbc377f60ba5c5640d31735cf8eb9af4de35f78b40e0e2970b1";
        Indicators indicators = indicators(
                "{ \"indicators\": [ { \"file:hashes.sha256\": [ \"" + sha256 + "\" ] } ] }");

        List<Object> sink = new ArrayList<>();
        Files files = parse(
                "files.json",
                json(String.format("[{\"path\":\"/system/app/sample\",\"sha256\":\"%s\"}]", sha256)),
                sink,
                f -> f.setIndicators(indicators));

        assertEquals(1, files.detected.size());
        assertDetection(files.detected, DetectionType.IOC_MATCH, AlertLevel.CRITICAL);
        assertDetectionValueContains(files.detected, DetectionType.IOC_MATCH, sha256);
    }
}
