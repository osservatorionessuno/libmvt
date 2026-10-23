package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;
import org.osservatorionessuno.libmvt.common.DetectionType;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.*;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionCount;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.streamArtifact;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.streamRecords;

/**
 * Pins behaviour from mvt-project/mvt#914 (per-record dumpsys settings).
 */
public class DumpsysSettingsTest {

    private static List<Object> parseFixture() throws Exception {
        return streamRecords(
                DumpsysSettings::new,
                "dumpsys.txt",
                ResourcesUtils.readResource("android_data/dumpsys_settings.txt"));
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> find(List<Object> parsed, String name) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Object record : parsed) {
            Map<String, Object> row = (Map<String, Object>) record;
            if (name.equals(row.get("name"))) out.add(row);
        }
        return out;
    }

    @Test
    public void testParsing() throws Exception {
        List<Object> parsed = parseFixture();
        assertEquals(12, parsed.size());

        @SuppressWarnings("unchecked")
        Map<String, Object> first = (Map<String, Object>) parsed.get(0);
        assertEquals("config", first.get("namespace"));
        assertEquals("0", first.get("user"));
        assertEquals("682", first.get("_id"));
        assertEquals("namespace_one/blocked_components", first.get("name"));
        assertEquals("com.example.services", first.get("pkg"));
        assertEquals(
                "com.android.settings,com.android.vending,\ncom.example.dialer,\ncom.example.camera",
                first.get("value"));
        assertEquals(
                "com.android.settings,\n  com.android.vending,\n  com.example.dialer",
                first.get("default"));
        assertEquals("false", first.get("defaultSystemSet"));
        assertEquals(List.of(), first.get("history"));
    }

    @Test
    public void testMultilineValuesAreKeptWhole() throws Exception {
        List<Object> parsed = parseFixture();
        assertEquals(
                "com.example.messaging,\ncom.example.chat",
                find(parsed, "namespace_one/allowed_packages").get(0).get("value"));
        assertEquals(
                "{\n  \"version\": 1,\n  \"data\": [\n    {\n      \"number\": 10000,\n"
                        + "      \"package_name\": \"com.example.widget\"\n    }\n  ]\n}",
                find(parsed, "widget_instance_data").get(0).get("value"));
    }

    @Test
    public void testTrailingDefaultIsNotPartOfTheValue() throws Exception {
        Map<String, Object> record = find(parseFixture(), "namespace_one/streaming_blocked_components").get(0);
        assertEquals("com.example.dialer,com.example.camera", record.get("value"));
        assertEquals("com.android.settings,\n  com.android.vending", record.get("default"));
    }

    @Test
    public void testTrailingMetadataIsNotPartOfTheValue() throws Exception {
        List<Object> parsed = parseFixture();

        Map<String, Object> notifications = find(parsed, "lock_screen_show_notifications").get(0);
        assertEquals("1", notifications.get("value"));
        assertEquals("true", notifications.get("defaultSystemSet"));
        assertEquals("true", notifications.get("isValuePreservedInRestore"));

        // user 10 accessibility: tag follows the value (no default).
        Map<String, Object> accessibilityUser10 = find(parsed, "accessibility_enabled").get(1);
        assertEquals("0", accessibilityUser10.get("value"));
        assertEquals("null", accessibilityUser10.get("tag"));
        assertFalse(accessibilityUser10.containsKey("default"));

        Map<String, Object> sendError = find(parsed, "send_action_app_error").get(0);
        assertEquals("1", sendError.get("value"));
        assertEquals("false", sendError.get("isValuePreservedInRestore"));
    }

    @Test
    public void testDumpsAfterTheLastBlockAreNotPartOfTheLastRow() throws Exception {
        List<Object> parsed = parseFixture();
        @SuppressWarnings("unchecked")
        Map<String, Object> last = (Map<String, Object>) parsed.get(parsed.size() - 1);
        assertEquals("secure", last.get("namespace"));
        assertEquals("10", last.get("user"));
        assertEquals("311", last.get("_id"));
        assertEquals("accessibility_enabled", last.get("name"));
        assertEquals("android", last.get("pkg"));
        assertEquals("0", last.get("value"));
        assertEquals("null", last.get("tag"));
        assertEquals(List.of(), last.get("history"));
        assertFalse(Objects.toString(last.get("value"), "").contains("GENERATION"));
    }

    @Test
    public void testRepeatedNamesAreKeptAsSeparateRecords() throws Exception {
        List<Object> parsed = parseFixture();
        List<Map<String, Object>> widgets = find(parsed, "widget_instance_data");
        assertEquals(List.of("771", "41654"), widgets.stream().map(r -> r.get("_id")).toList());

        List<Map<String, Object>> accessibility = find(parsed, "accessibility_enabled");
        assertEquals(
                List.of(List.of("0", "1"), List.of("10", "0")),
                accessibility.stream().map(r -> List.of(r.get("user"), r.get("value"))).toList());
    }

    @Test
    public void testSettingWithoutRecordingPackage() throws Exception {
        Map<String, Object> record = find(parseFixture(), "hidden_api_blacklist_exemptions").get(0);
        assertFalse(record.containsKey("pkg"));
        assertEquals("{null}", record.get("value"));
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testHistoryTimestampsResolvedAgainstSectionEnd() throws Exception {
        Map<String, Object> record = find(parseFixture(), "development_settings_enabled").get(0);
        List<Map<String, Object>> history = (List<Map<String, Object>>) record.get("history");
        assertEquals(2, history.size());
        assertEquals("2021-11-02 11:21:22.212000", history.get(0).get("timestamp"));
        assertEquals("null", history.get(0).get("oldValue"));
        assertEquals("1", history.get(0).get("newValue"));
        assertEquals("com.android.settings", history.get(0).get("pkg"));
        assertEquals("2022-03-14 09:02:11.100000", history.get(1).get("timestamp"));
        assertEquals("1", history.get(1).get("oldValue"));
        assertEquals("0", history.get(1).get("newValue"));
        assertEquals("com.example.updater", history.get(1).get("pkg"));
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testHistoryWithoutASectionEndHasNoTimestamp() {
        DumpsysSettings settings = new DumpsysSettings();
        List<Object> records = new ArrayList<>();
        settings.setRecordObserver(records::add);
        settings.parseSection(
                "SECURE SETTINGS (user 0)\n"
                        + "_id:240 name:accessibility_enabled pkg:android value:1\n"
                        + "\tHistory (accessibility_enabled)\n"
                        + "\t\ttime:03-28 22:41:07.980 mode:update oldValue:0 newValue:1 "
                        + "package:com.example.helper\n");

        Map<String, Object> record = (Map<String, Object>) records.get(0);
        List<Map<String, Object>> history = (List<Map<String, Object>>) record.get("history");
        assertNull(history.get(0).get("timestamp"));
        assertEquals("0", history.get(0).get("oldValue"));
        assertEquals("1", history.get(0).get("newValue"));
        assertEquals("com.example.helper", history.get(0).get("pkg"));
    }

    @Test
    public void testLeapDayHistoryKeepsItsTimestamp() {
        LocalDateTime end = LocalDateTime.of(2024, 3, 5, 23, 14, 28);
        assertEquals(
                "2024-02-29 22:41:07.980000",
                DumpsysSettings.resolveTimestamp("02-29 22:41:07.980", end));
    }

    @Test
    public void testLeapDayHistoryResolvedToTheLastLeapYear() {
        assertEquals(
                "2024-02-29 22:41:07.980000",
                DumpsysSettings.resolveTimestamp(
                        "02-29 22:41:07.980", LocalDateTime.of(2025, 3, 1, 10, 0, 0)));
        assertEquals(
                "2020-02-29 22:41:07.980000",
                DumpsysSettings.resolveTimestamp(
                        "02-29 22:41:07.980", LocalDateTime.of(2024, 1, 10, 10, 0, 0)));
    }

    @Test
    public void testLeapDayHistoryBeforeALeapDayAfterASkippedCentury() {
        assertEquals(
                "2096-02-29 22:41:07.980000",
                DumpsysSettings.resolveTimestamp(
                        "02-29 22:41:07.980", LocalDateTime.of(2104, 1, 10, 10, 0, 0)));
    }

    @Test
    public void testDangerousSettingIsDetected() throws Exception {
        DumpsysSettings settings = streamArtifact(
                DumpsysSettings::new,
                "dumpsys.txt",
                ResourcesUtils.readResource("android_data/dumpsys_settings.txt"));

        assertDetectionCount(settings.detected, DetectionType.DANGEROUS_SETTINGS, 1);
        assertTrue(settings.detected.stream().anyMatch(d ->
                d.getValue().contains("enabled accessibility services")
                        && d.getValue().contains("accessibility_enabled")
                        && d.getValue().contains("1")));
    }
}
