package org.osservatorionessuno.libmvt.common;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public final class DetectionTestUtils {

    private DetectionTestUtils() {
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
