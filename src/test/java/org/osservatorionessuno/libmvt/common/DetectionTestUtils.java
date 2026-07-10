package org.osservatorionessuno.libmvt.common;

import org.osservatorionessuno.libmvt.android.artifacts.AndroidArtifact;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public final class DetectionTestUtils {

    private static final Path TEST_IOCS_DIR =
            Paths.get("src", "test", "resources", "iocs");

    private DetectionTestUtils() {
    }

    public static Indicators loadTestIndicators() throws Exception {
        Indicators indicators = new Indicators();
        indicators.loadFromDirectory(TEST_IOCS_DIR.toFile());
        return indicators;
    }

    public static Indicators indicatorsFromJson(String json) throws Exception {
        Path dir = Files.createTempDirectory("mvt-iocs-");
        Files.writeString(dir.resolve("iocs.json"), json, StandardCharsets.UTF_8);
        Indicators indicators = new Indicators();
        indicators.loadFromDirectory(dir.toFile());
        return indicators;
    }

    public static void runIocCheck(Artifact artifact) throws Exception {
        artifact.setIndicators(loadTestIndicators());
        artifact.checkIndicators();
    }

    public static <T extends Artifact> T parseArtifact(
            Supplier<T> factory,
            String path,
            InputStream data) throws Exception {
        return parseArtifact(factory, path, data, ignored -> {});
    }

    public static <T extends Artifact> T parseArtifact(
            Supplier<T> factory,
            String path,
            InputStream data,
            Consumer<T> configure) throws Exception {
        T artifact = factory.get();
        configure.accept(artifact);
        artifact.parse(new AbstractInput(path, data) {});
        return artifact;
    }

    public static <T extends AndroidArtifact> T parseAndroidArtifact(
            Supplier<T> factory,
            String path,
            InputStream data) throws Exception {
        return parseArtifact(factory, path, data, artifact -> artifact.setStringResolver(new JvmMapStringResolver()));
    }

    public static void assertDetection(
            List<Detection> detections,
            DetectionType type,
            AlertLevel level) {
        assertTrue(
                hasDetection(detections, type, level),
                "expected detection id=" + type.getId() + " level=" + level);
    }

    public static void assertDetectionValueContains(
            List<Detection> detections,
            DetectionType type,
            String needle) {
        assertTrue(
                anyDetectionValueContains(detections, type, null, needle),
                "expected detection id=" + type.getId() + " with value containing: " + needle);
    }

    public static void assertDetectionValueContains(
            List<Detection> detections,
            DetectionType type,
            AlertLevel level,
            String needle) {
        assertTrue(
                anyDetectionValueContains(detections, type, level, needle),
                "expected detection id=" + type.getId() + " level=" + level
                        + " with value containing: " + needle);
    }

    public static void assertDetectionValue(
            List<Detection> detections,
            DetectionType type,
            List<String> expectedValue) {
        assertFalse(detections.isEmpty(), "no detections");
        for (Detection detection : detections) {
            if (!type.getId().equals(detection.getId())) continue;
            assertEquals(expectedValue, detection.getValue());
            return;
        }
        throw new AssertionError("no detection with id=" + type.getId());
    }

    public static void assertDetectionCount(
            List<Detection> detections,
            DetectionType type,
            int expectedCount) {
        int count = 0;
        for (Detection detection : detections) {
            if (type.getId().equals(detection.getId())) count++;
        }
        assertEquals(expectedCount, count, "detection count for id=" + type.getId());
    }

    public static boolean anyDetectionValueContains(
            List<Detection> detections,
            DetectionType type,
            AlertLevel level,
            String needle) {
        if (detections == null || needle == null) return false;
        for (Detection detection : detections) {
            if (!type.getId().equals(detection.getId())) continue;
            if (level != null && !type.getLevel().equals(level)) continue;
            for (String part : detection.getValue()) {
                if (part != null && part.contains(needle)) return true;
            }
        }
        return false;
    }

    private static boolean hasDetection(
            List<Detection> detections,
            DetectionType type,
            AlertLevel level) {
        if (detections == null) return false;
        for (Detection detection : detections) {
            if (type.getId().equals(detection.getId()) && type.getLevel().equals(level)) {
                return true;
            }
        }
        return false;
    }
}
