package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;
import org.osservatorionessuno.libmvt.common.Artifact;
import org.osservatorionessuno.libmvt.common.DetectionType;
import org.osservatorionessuno.libmvt.common.GroupedDetection;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionCount;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionValue;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionValueContains;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.streamArtifact;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.streamRecords;

public class SettingsTest {

    private static List<Settings.Record> dumpsysRecords() throws Exception {
        try (InputStream data = ResourcesUtils.readResource("android_data/dumpsys_settings.txt")) {
            return records(streamRecords(Settings::new, "dumpsys.txt", data));
        }
    }

    private static List<Settings.Record> records(List<Object> parsed) {
        List<Settings.Record> records = new ArrayList<>();
        for (Object o : parsed) records.add((Settings.Record) o);
        return records;
    }

    private static List<Settings.Record> find(List<Settings.Record> records, String name) {
        return records.stream().filter(r -> name.equals(r.name)).collect(Collectors.toList());
    }

    private static InputStream text(String s) {
        return new ByteArrayInputStream(s.getBytes(StandardCharsets.UTF_8));
    }

    // --- key=value files ---------------------------------------------------------------------

    @Test
    public void testKeyValueFileYieldsOneRecordPerRow() throws Exception {
        List<Settings.Record> parsed;
        try (InputStream data = ResourcesUtils.readResource("androidqf/settings_secure.txt")) {
            parsed = records(streamRecords(Settings::new, "settings_secure.txt", data));
        }

        assertEquals(3, parsed.size());
        Settings.Record first = parsed.get(0);
        assertEquals("secure", first.namespace);
        assertNull(first.user);
        assertEquals("accessibility_enabled", first.name);
        assertEquals("1", first.value);
        assertEquals("0", find(parsed, "package_verifier_enable").get(0).value);
    }

    @Test
    public void testKeyValueFileDangerousSettings() throws Exception {
        Settings settings;
        try (InputStream data = ResourcesUtils.readResource("androidqf/settings_secure.txt")) {
            settings = streamArtifact(Settings::new, "settings_secure.txt", data);
        }

        assertEquals(2, settings.detected.size());
        assertDetectionCount(settings.detected, DetectionType.DANGEROUS_SETTINGS, 2);
        assertDetectionValueContains(settings.detected, DetectionType.DANGEROUS_SETTINGS, "accessibility_enabled");
        assertDetectionValueContains(settings.detected, DetectionType.DANGEROUS_SETTINGS, "package_verifier_enable");
        assertDetectionValue(
                settings.detected,
                DetectionType.DANGEROUS_SETTINGS,
                List.of("enabled accessibility services", "secure", "accessibility_enabled", "1"));
    }

    // --- dumpsys section ---------------------------------------------------------------------

    @Test
    public void testDumpsysParsing() throws Exception {
        List<Settings.Record> records = dumpsysRecords();

        assertEquals(12, records.size());
        Set<String> namespaces = records.stream().map(r -> r.namespace).collect(Collectors.toSet());
        assertEquals(Set.of("config", "global", "secure"), namespaces);

        Settings.Record first = records.get(0);
        assertEquals("config", first.namespace);
        assertEquals("0", first.user);
        assertEquals("682", first.id);
        assertEquals("namespace_one/blocked_components", first.name);
        assertEquals("com.example.services", first.pkg);
        assertEquals(
                "com.android.settings,com.android.vending,\ncom.example.dialer,\ncom.example.camera",
                first.value);
        assertEquals(
                "com.android.settings,\n        com.android.vending,\n        com.example.dialer",
                first.defaultValue);
        assertEquals("false", first.defaultSystemSet);
    }

    @Test
    public void testMultilineValuesAreKeptWhole() throws Exception {
        List<Settings.Record> records = dumpsysRecords();

        assertEquals("com.example.messaging,\ncom.example.chat",
                find(records, "namespace_one/allowed_packages").get(0).value);
        assertEquals(
                "{\n  \"version\": 1,\n  \"data\": [\n    {\n      \"number\": 10000,\n"
                        + "      \"package_name\": \"com.example.widget\"\n    }\n  ]\n}",
                find(records, "widget_instance_data").get(0).value);
    }

    @Test
    public void testTrailingDefaultIsNotPartOfTheValue() throws Exception {
        Settings.Record record = find(dumpsysRecords(), "namespace_one/streaming_blocked_components").get(0);

        assertEquals("com.example.dialer,com.example.camera", record.value);
        assertEquals("com.android.settings,\n        com.android.vending", record.defaultValue);
    }

    @Test
    public void testTrailingMetadataIsNotPartOfTheValue() throws Exception {
        List<Settings.Record> records = dumpsysRecords();

        Settings.Record record = find(records, "lock_screen_show_notifications").get(0);
        assertEquals("1", record.value);
        assertEquals("true", record.defaultSystemSet);
        assertEquals("true", record.valuePreservedInRestore);

        // Without a default, the tag or the restore token follows the value.
        record = find(records, "accessibility_enabled").get(1);
        assertEquals("0", record.value);
        assertEquals("null", record.tag);
        assertNull(record.defaultValue);

        record = find(records, "send_action_app_error").get(0);
        assertEquals("1", record.value);
        assertEquals("false", record.valuePreservedInRestore);
    }

    @Test
    public void testDumpsAfterTheLastBlockAreNotPartOfTheLastRow() throws Exception {
        List<Settings.Record> records = dumpsysRecords();
        Settings.Record last = records.get(records.size() - 1);

        assertEquals("secure", last.namespace);
        assertEquals("10", last.user);
        assertEquals("311", last.id);
        assertEquals("accessibility_enabled", last.name);
        assertEquals("android", last.pkg);
        assertEquals("0", last.value);
        assertEquals("null", last.tag);
    }

    @Test
    public void testRepeatedNamesAreKeptAsSeparateRecords() throws Exception {
        List<Settings.Record> records = dumpsysRecords();

        List<Settings.Record> widgets = find(records, "widget_instance_data");
        assertEquals(List.of("771", "41654"), widgets.stream().map(r -> r.id).collect(Collectors.toList()));

        List<Settings.Record> accessibility = find(records, "accessibility_enabled");
        assertEquals(2, accessibility.size());
        assertEquals("0", accessibility.get(0).user);
        assertEquals("1", accessibility.get(0).value);
        assertEquals("10", accessibility.get(1).user);
        assertEquals("0", accessibility.get(1).value);
    }

    @Test
    public void testSettingWithoutRecordingPackage() throws Exception {
        Settings.Record record = find(dumpsysRecords(), "hidden_api_blacklist_exemptions").get(0);

        assertNull(record.pkg);
        assertEquals("{null}", record.value);
    }

    @Test
    public void testOnlyRowsOfTheSettingsSectionBecomeRecords() throws Exception {
        List<Settings.Record> records = dumpsysRecords();

        // Not the version: line, the generation registry, nor the next service.
        assertTrue(records.stream().allMatch(r -> r.id != null && r.name != null && r.value != null));
        assertTrue(records.stream().noneMatch(r -> r.name.contains("AFTER_SETTINGS")));
    }

    @Test
    public void testDumpsysDangerousSettingOnThePrimaryUserIsNotLabelled() throws Exception {
        Settings settings;
        try (InputStream data = ResourcesUtils.readResource("android_data/dumpsys_settings.txt")) {
            settings = streamArtifact(Settings::new, "dumpsys.txt", data);
        }

        // accessibility_enabled is 1 for user 0 and 0 for user 10; send_action_app_error is safe.
        assertDetectionCount(settings.detected, DetectionType.DANGEROUS_SETTINGS, 1);
        assertDetectionValue(
                settings.detected,
                DetectionType.DANGEROUS_SETTINGS,
                List.of("enabled accessibility services", "secure", "accessibility_enabled", "1"));
    }

    @Test
    public void testDumpsysDangerousSettingOnAnotherUserIsLabelledAndAlertedOnce() throws Exception {
        String dump = "DUMP OF SERVICE settings:\n"
                + "SECURE SETTINGS (user 0)\n"
                + "_id:240 name:accessibility_enabled pkg:android value:0 default:0 defaultSystemSet:true\n"
                + "\n"
                + "SECURE SETTINGS (user 10)\n"
                + "_id:311 name:accessibility_enabled pkg:android value:1 tag:null\n"
                + "_id:312 name:package_verifier_user_consent pkg:android value:-1\n"
                + "\n"
                + "--------- 0.019s was the duration of dumpsys settings, ending at: 2022-03-29 23:14:28\n";
        Settings settings = streamArtifact(Settings::new, "dumpsys.txt", text(dump));

        assertDetectionCount(settings.detected, DetectionType.DANGEROUS_SETTINGS, 2);
        assertDetectionValue(
                settings.detected,
                DetectionType.DANGEROUS_SETTINGS,
                List.of("enabled accessibility services", "secure", "accessibility_enabled", "1", "user 10"));
        assertDetectionValueContains(settings.detected, DetectionType.DANGEROUS_SETTINGS, "package_verifier_user_consent");
    }

    @Test
    public void testSameFindingFromBothSourcesIsGroupedOnce() throws Exception {
        // A capture carries settings_secure.txt (user 0, unlabelled) and dumpsys.txt (user 0 named).
        Settings fromFile = streamArtifact(Settings::new, "settings_secure.txt", text("accessibility_enabled=1\n"));
        Settings fromDumpsys;
        try (InputStream data = ResourcesUtils.readResource("android_data/dumpsys_settings.txt")) {
            fromDumpsys = streamArtifact(Settings::new, "dumpsys.txt", data);
        }
        Map<String, Artifact> results = new LinkedHashMap<>();
        results.put("settings_secure.txt", fromFile);
        results.put("dumpsys.txt", fromDumpsys);

        List<GroupedDetection> grouped = GroupedDetection.fromArtifacts(results);
        assertEquals(1, grouped.size());
        assertEquals(DetectionType.DANGEROUS_SETTINGS.getId(), grouped.get(0).getId());
        assertEquals(1, grouped.get(0).getDetections().size());
    }

    @Test
    public void testSplitFieldsSkipsKeysThatAreNotPrinted() {
        Map<String, String> fields = Settings.splitFields(
                "_id:1 name:a value:x y z tag:null",
                new String[] {"_id", "name", "pkg", "value", "default", "tag"});

        assertEquals("1", fields.get("_id"));
        assertEquals("a", fields.get("name"));
        assertNull(fields.get("pkg"));
        assertEquals("x y z", fields.get("value"));
        assertNull(fields.get("default"));
        assertEquals("null", fields.get("tag"));
    }
}
