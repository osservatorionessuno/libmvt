package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;
import org.osservatorionessuno.libmvt.common.AbstractInput;
import org.osservatorionessuno.libmvt.common.AlertLevel;
import org.osservatorionessuno.libmvt.common.DetectionType;
import org.osservatorionessuno.libmvt.common.JvmMapStringResolver;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.osservatorionessuno.libmvt.ResourcesUtils.readResourceBytes;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetection;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionCount;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionValue;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionValueContains;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.indicatorsFromJson;

public class TombstoneCrashesTest {

    @Test
    public void testPaths() {
        assertEquals(List.of("**/tombstone*"), new TombstoneCrashes().paths());
    }

    @Test
    public void testParsing() throws Exception {
        TombstoneCrashes tc = new TombstoneCrashes();
        InputStream data = ResourcesUtils.readResource("android_data/tombstone_process.txt");
        tc.parse(new AbstractInput("dummy", data) {});

        assertEquals(1, tc.getResults().size());

        @SuppressWarnings("unchecked")
        Map<String, Object> rec = (Map<String, Object>) tc.getResults().get(0);
        assertEquals("mtk.ape.decoder", rec.get("process_name"));
        assertEquals(25541, rec.get("pid"));
        assertEquals(21307, rec.get("tid"));
        assertEquals(1046, rec.get("uid"));
        assertEquals(
                "/vendor/bin/hw/android.hardware.media.c2@1.2-mediatek",
                rec.get("binary_path"));
        assertEquals(
                "/vendor/bin/hw/android.hardware.media.c2@1.2-mediatek",
                ((List<?>) rec.get("command_line")).get(0));
        assertEquals("2023-04-12 12:32:40.518290", rec.get("timestamp"));
        assertEquals(
                "android.hardware.media.c2@1.2-mediatek",
                TombstoneCrashes.crashLabel(rec));
    }

    @Test
    public void testParseProtobuf() throws Exception {
        TombstoneCrashes tc = new TombstoneCrashes();
        byte[] data = readResourceBytes("android_data/tombstone_process.pb");
        tc.parse(new AbstractInput(
                "FS/data/tombstones/tombstone_process.pb",
                new ByteArrayInputStream(data)) {});

        assertEquals(1, tc.getResults().size());

        @SuppressWarnings("unchecked")
        Map<String, Object> rec = (Map<String, Object>) tc.getResults().get(0);
        assertEquals("mtk.ape.decoder", rec.get("process_name"));
        assertEquals(25541, rec.get("pid"));
        assertEquals(1046, rec.get("uid"));
        assertEquals(
                "/vendor/bin/hw/android.hardware.media.c2@1.2-mediatek",
                ((List<?>) rec.get("command_line")).get(0));
        assertEquals(
                "/vendor/bin/hw/android.hardware.media.c2@1.2-mediatek",
                rec.get("binary_path"));
        assertEquals("2023-04-12 12:32:40.518290", rec.get("timestamp"));
    }

    @Test
    public void testParsePidLineWithPpidKeepsCrashThreadName() throws Exception {
        // Newer Android dumps insert ppid between pid and tid. Positional parsers miss `name:`.
        String dump = String.join("\n",
                "Timestamp: 2026-07-16 13:10:28.933796599+0200",
                "Cmdline: /vendor/bin/hw/android.hardware.biometrics.fingerprint-service.goodix",
                "pid: 1348, ppid: 1, tid: 1910, name: android.hardwar  >>> /vendor/bin/hw/android.hardware.biometrics.fingerprint-service.goodix <<<",
                "uid: 1000",
                // Later per-thread dump must not replace the crashing thread / binary identity.
                "pid: 1348, ppid: 1, tid: 6004, name: SensorPollingWo  >>> /vendor/bin/hw/android.hardware.biometrics.fingerprint-service.goodix <<<",
                "uid: 1000");

        @SuppressWarnings("unchecked")
        Map<String, Object> rec = parseText(dump);

        assertEquals("android.hardwar", rec.get("process_name"));
        assertEquals(1348, rec.get("pid"));
        assertEquals(1910, rec.get("tid"));
        assertEquals(1000, rec.get("uid"));
        assertEquals(
                "/vendor/bin/hw/android.hardware.biometrics.fingerprint-service.goodix",
                rec.get("binary_path"));
        assertEquals(
                "android.hardware.biometrics.fingerprint-service.goodix",
                TombstoneCrashes.crashLabel(rec));
    }

    @Test
    public void testParseLegacyPidLineWithoutPpid() throws Exception {
        String dump = String.join("\n",
                "Timestamp: 2023-04-12 12:32:40.518290+0200",
                "Cmd line: /vendor/bin/hw/android.hardware.media.c2@1.2-mediatek",
                "pid: 25541, tid: 21307, name: mtk.ape.decoder  >>> /vendor/bin/hw/android.hardware.media.c2@1.2-mediatek <<<",
                "uid: 1046");

        @SuppressWarnings("unchecked")
        Map<String, Object> rec = parseText(dump);

        assertEquals("mtk.ape.decoder", rec.get("process_name"));
        assertEquals(25541, rec.get("pid"));
        assertEquals(21307, rec.get("tid"));
        assertEquals(
                "/vendor/bin/hw/android.hardware.media.c2@1.2-mediatek",
                rec.get("binary_path"));
        assertEquals(
                "/vendor/bin/hw/android.hardware.media.c2@1.2-mediatek",
                ((List<?>) rec.get("command_line")).get(0));
    }

    @Test
    public void testParsePackageProcessSetsPackageNameFromBinaryPath() throws Exception {
        String dump = String.join("\n",
                "Timestamp: 2026-01-01 00:00:00.000000+0000",
                "Cmdline: com.example.app",
                "pid: 42, tid: 42, name: example.app  >>> com.example.app <<<",
                "uid: 10123");

        @SuppressWarnings("unchecked")
        Map<String, Object> rec = parseText(dump);

        assertEquals("com.example.app", rec.get("package_name"));
        assertEquals("com.example.app", rec.get("binary_path"));
        assertEquals("com.example.app", TombstoneCrashes.crashLabel(rec));
    }

    @Test
    public void testParsePidLineRequiresBinaryPathWhenArrowPresent() {
        Map<String, Object> rec = new HashMap<>();
        assertThrows(
                IllegalArgumentException.class,
                () -> TombstoneCrashes.parsePidLine("pid: 1, tid: 1, name: x  >>>  <<<", rec));
    }

    @Test
    public void testCrashLabelPrefersBinaryThenCmdlineThenPackage() {
        Map<String, Object> all = new HashMap<>();
        all.put("binary_path", "/system/bin/surfaceflinger");
        all.put("command_line", List.of("/ignored/cmdline"));
        all.put("package_name", "com.ignored");
        assertEquals("surfaceflinger", TombstoneCrashes.crashLabel(all));

        Map<String, Object> cmdlineOnly = new HashMap<>();
        cmdlineOnly.put("command_line", List.of("/vendor/bin/hw/android.hardware.foo"));
        assertEquals("android.hardware.foo", TombstoneCrashes.crashLabel(cmdlineOnly));

        Map<String, Object> packageOnly = new HashMap<>();
        packageOnly.put("package_name", "com.example.app");
        assertEquals("com.example.app", TombstoneCrashes.crashLabel(packageOnly));

        assertEquals("", TombstoneCrashes.crashLabel(Map.of()));
    }

    @Test
    public void testCheckIndicatorsUidUsesBinaryBasenameAndTimestamp() throws Exception {
        String dump = String.join("\n",
                "Timestamp: 2026-07-16 13:10:28.933796+0200",
                "Cmdline: /vendor/bin/hw/android.hardware.biometrics.fingerprint-service.goodix",
                "pid: 1348, ppid: 1, tid: 1910, name: android.hardwar  >>> /vendor/bin/hw/android.hardware.biometrics.fingerprint-service.goodix <<<",
                "uid: 1000");

        TombstoneCrashes tc = parseWithEmptyIndicators(dump);

        assertDetection(tc.detected, DetectionType.TOMBSTONE_CRASHES_UID, AlertLevel.MEDIUM);
        assertDetectionValue(
                tc.detected,
                DetectionType.TOMBSTONE_CRASHES_UID,
                List.of(
                        "android.hardware.biometrics.fingerprint-service.goodix",
                        "1000",
                        "2026-07-16 13:10:28.933796"));
    }

    @Test
    public void testCheckIndicatorsFlagsRootAndShellUids() throws Exception {
        for (int uid : new int[] {0, 2000}) {
            String dump = String.join("\n",
                    "Timestamp: 2026-01-01 00:00:00.000000+0000",
                    "Cmdline: /system/bin/surfaceflinger",
                    "pid: 1, tid: 1, name: surfaceflinger  >>> /system/bin/surfaceflinger <<<",
                    "uid: " + uid);

            TombstoneCrashes tc = parseWithEmptyIndicators(dump);
            assertDetectionCount(tc.detected, DetectionType.TOMBSTONE_CRASHES_UID, 1);
            assertDetectionValueContains(
                    tc.detected, DetectionType.TOMBSTONE_CRASHES_UID, Integer.toString(uid));
            assertDetectionValueContains(
                    tc.detected, DetectionType.TOMBSTONE_CRASHES_UID, "surfaceflinger");
        }
    }

    @Test
    public void testCheckIndicatorsIgnoresNonSuspiciousUid() throws Exception {
        // Fixture uid 1046 (mediacodec) must not raise TOMBSTONE_CRASHES_UID.
        TombstoneCrashes tc = new TombstoneCrashes();
        tc.setStringResolver(new JvmMapStringResolver());
        try (InputStream data = ResourcesUtils.readResource("android_data/tombstone_process.txt")) {
            tc.parse(new AbstractInput("tombstone_process", data) {});
        }
        tc.setIndicators(indicatorsFromJson("{ \"indicators\": [] }"));
        tc.checkIndicators();

        assertDetectionCount(tc.detected, DetectionType.TOMBSTONE_CRASHES_UID, 0);
    }

    @Test
    public void testCheckIndicatorsWithoutIndicatorsDoesNothing() throws Exception {
        TombstoneCrashes tc = new TombstoneCrashes();
        String dump = String.join("\n",
                "Timestamp: 2026-01-01 00:00:00.000000+0000",
                "pid: 1, tid: 1, name: init  >>> /system/bin/init <<<",
                "uid: 0");
        tc.parse(new AbstractInput(
                "tombstone",
                new ByteArrayInputStream(dump.getBytes(StandardCharsets.UTF_8))) {});
        tc.checkIndicators();
        assertTrue(tc.detected.isEmpty());
    }

    @Test
    public void testCheckIndicatorsKeepsDistinctTimestamps() throws Exception {
        TombstoneCrashes tc = new TombstoneCrashes();
        tc.setStringResolver(new JvmMapStringResolver());
        tc.setIndicators(indicatorsFromJson("{ \"indicators\": [] }"));

        // Same binary/uid at two times must not collapse when detections are grouped by value.
        tc.getResults().add(Map.of(
                "binary_path", "/vendor/bin/hw/android.hardware.biometrics.fingerprint-service.goodix",
                "uid", 1000,
                "timestamp", "2026-07-16 13:10:28.933796"));
        tc.getResults().add(Map.of(
                "binary_path", "/vendor/bin/hw/android.hardware.biometrics.fingerprint-service.goodix",
                "uid", 1000,
                "timestamp", "2026-03-16 17:15:00.099791"));
        tc.checkIndicators();

        assertDetectionCount(tc.detected, DetectionType.TOMBSTONE_CRASHES_UID, 2);
        assertEquals(
                2,
                org.osservatorionessuno.libmvt.common.GroupedDetection.group(tc.detected, null)
                        .stream()
                        .filter(g -> DetectionType.TOMBSTONE_CRASHES_UID.getId().equals(g.getId()))
                        .findFirst()
                        .orElseThrow()
                        .getDetections()
                        .size());
    }

    @Test
    public void testCheckIndicators() throws Exception {
        TombstoneCrashes tc = new TombstoneCrashes();
        tc.setStringResolver(new JvmMapStringResolver());
        try (InputStream data = ResourcesUtils.readResource("android_data/tombstone_process.txt")) {
            tc.parse(new AbstractInput("tombstone_process", data) {});
        }

        tc.setIndicators(indicatorsFromJson(
                "{ \"indicators\": [ { \"process:name\": [ \"mtk.ape.decoder\" ] } ] }"));
        tc.checkIndicators();

        assertFalse(tc.detected.isEmpty());
        assertDetection(tc.detected, DetectionType.IOC_MATCH, AlertLevel.CRITICAL);
        assertDetectionValueContains(tc.detected, DetectionType.IOC_MATCH, "mtk.ape.decoder");
    }

    @Test
    public void testCheckIndicatorsMatchesCmdlineProcessBasename() throws Exception {
        String dump = String.join("\n",
                "Timestamp: 2026-01-01 00:00:00.000000+0000",
                "Cmdline: /vendor/bin/hw/evil.hardware.service",
                "pid: 9, tid: 9, name: evil.hardware.  >>> /vendor/bin/hw/evil.hardware.service <<<",
                "uid: 1046");

        TombstoneCrashes tc = new TombstoneCrashes();
        tc.setStringResolver(new JvmMapStringResolver());
        tc.parse(new AbstractInput(
                "tombstone",
                new ByteArrayInputStream(dump.getBytes(StandardCharsets.UTF_8))) {});
        tc.setIndicators(indicatorsFromJson(
                "{ \"indicators\": [ { \"process:name\": [ \"evil.hardware.service\" ] } ] }"));
        tc.checkIndicators();

        assertDetection(tc.detected, DetectionType.IOC_MATCH, AlertLevel.CRITICAL);
        assertDetectionValueContains(
                tc.detected, DetectionType.IOC_MATCH, "evil.hardware.service");
    }

    private static Map<String, Object> parseText(String dump) throws Exception {
        TombstoneCrashes tc = new TombstoneCrashes();
        tc.parse(new AbstractInput(
                "tombstone",
                new ByteArrayInputStream(dump.getBytes(StandardCharsets.UTF_8))) {});
        assertEquals(1, tc.getResults().size());
        @SuppressWarnings("unchecked")
        Map<String, Object> rec = (Map<String, Object>) tc.getResults().get(0);
        return rec;
    }

    private static TombstoneCrashes parseWithEmptyIndicators(String dump) throws Exception {
        TombstoneCrashes tc = new TombstoneCrashes();
        tc.setStringResolver(new JvmMapStringResolver());
        tc.parse(new AbstractInput(
                "tombstone",
                new ByteArrayInputStream(dump.getBytes(StandardCharsets.UTF_8))) {});
        tc.setIndicators(indicatorsFromJson("{ \"indicators\": [] }"));
        tc.checkIndicators();
        return tc;
    }
}
