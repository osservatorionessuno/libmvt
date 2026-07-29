package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;
import org.osservatorionessuno.libmvt.common.DetectionType;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.parseArtifact;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.streamRecords;

public class DumpsysAdbTest {

    @Test
    public void testParsing() throws Exception {
        List<Object> parsed = streamRecords(
                DumpsysAdb::new,
                "dumpsys.txt",
                ResourcesUtils.readResource("android_data/dumpsys_adb.txt"));
        assertEquals(1, parsed.size());

        @SuppressWarnings("unchecked")
        Map<String, Object> result = (Map<String, Object>) parsed.get(0);
        @SuppressWarnings("unchecked")
        List<Map<String, String>> keys = (List<Map<String, String>>) result.get("user_keys");
        assertEquals(1, keys.size());
        Map<String, String> first = keys.get(0);
        assertEquals("F0:A1:3D:8C:B3:F4:7B:09:9F:EE:8B:D8:38:2E:BD:C6", first.get("fingerprint"));
        assertEquals("user@linux", first.get("user"));
    }

    @Test
    public void testParsingXml() throws Exception {
        List<Object> parsed = streamRecords(
                DumpsysAdb::new,
                "dumpsys.txt",
                ResourcesUtils.readResource("android_data/dumpsys_adb_xml.txt"));
        assertEquals(1, parsed.size());

        @SuppressWarnings("unchecked")
        Map<String, Object> result = (Map<String, Object>) parsed.get(0);
        @SuppressWarnings("unchecked")
        List<Map<String, String>> keys = (List<Map<String, String>>) result.get("user_keys");
        assertEquals(1, keys.size());
        Map<String, String> first = keys.get(0);
        assertEquals("F0:0B:27:08:E3:68:7B:FA:4C:79:A2:B4:BF:0E:CF:70", first.get("fingerprint"));
        assertEquals("user@laptop", first.get("user"));
        @SuppressWarnings("unchecked")
        List<Map<String, String>> ks = (List<Map<String, String>>) result.get("keystore");
        assertEquals("user@laptop", ks.get(0).get("user"));
        assertEquals("F0:0B:27:08:E3:68:7B:FA:4C:79:A2:B4:BF:0E:CF:70", ks.get(0).get("fingerprint"));
        assertEquals("1628501829898", ks.get(0).get("last_connected"));
    }

    @Test
    public void testHostKeyDetectedSeparately() throws Exception {
        String data = ResourcesUtils.readResourceString("android_data/dumpsys_adb.txt");
        DumpsysAdb da = parseArtifact(
                DumpsysAdb::new,
                "dumpsys.txt",
                new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8)),
                a -> a.setHostKeys(List.of(extractUserKeyLine(data))));

        assertEquals(1, da.detected.size());
        assertEquals(DetectionType.ADB_HOST_FINGERPRINT.getId(), da.detected.get(0).getId());
    }

    @Test
    public void testUnknownKeyStillDetected() throws Exception {
        String data = ResourcesUtils.readResourceString("android_data/dumpsys_adb.txt");
        DumpsysAdb da = parseArtifact(
                DumpsysAdb::new,
                "dumpsys.txt",
                new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8)),
                a -> a.setHostKeys(List.of("QAAAAG5vdC10aGUtc2FtZS1rZXk= other@host")));

        assertEquals(1, da.detected.size());
        assertEquals(DetectionType.ADB_FINGERPRINT.getId(), da.detected.get(0).getId());
    }

    @Test
    public void testFingerprintOfAcceptsBlobAndFullLine() {
        String line = "QAAAAG5vdC10aGUtc2FtZS1rZXk= user@host";
        String blobOnly = "QAAAAG5vdC10aGUtc2FtZS1rZXk=";
        assertEquals(DumpsysAdb.fingerprintOf(blobOnly), DumpsysAdb.fingerprintOf(line));
        assertFalse(DumpsysAdb.fingerprintOf(line).isEmpty());
        assertEquals("", DumpsysAdb.fingerprintOf("!!!invalid!!! user@host"));
    }

    private static String extractUserKeyLine(String dumpsys) {
        for (String line : dumpsys.split("\n")) {
            String trimmed = line.trim();
            if (trimmed.startsWith("user_keys=")) return trimmed.substring(10);
        }
        throw new IllegalStateException("no user_keys line in resource");
    }
}
