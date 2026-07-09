package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.android.ArtifactModuleRegistry;
import org.osservatorionessuno.libmvt.ResourcesUtils;
import org.osservatorionessuno.libmvt.common.AbstractInput;
import org.osservatorionessuno.libmvt.common.AlertLevel;
import org.osservatorionessuno.libmvt.common.DetectionType;
import org.osservatorionessuno.libmvt.common.Indicators;
import org.osservatorionessuno.libmvt.common.JvmMapStringResolver;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.osservatorionessuno.libmvt.ResourcesUtils.readResourceBytes;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetection;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionValueContains;

public class TombstoneCrashesTest {

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
        assertEquals(1046, rec.get("uid"));
        assertEquals("/vendor/bin/hw/android.hardware.media.c2@1.2-mediatek",
                ((List<?>) rec.get("command_line")).get(0));
        assertEquals("2023-04-12 12:32:40.518290", rec.get("timestamp"));
    }

    @Test
    public void testParseProtobuf() throws Exception {
        TombstoneCrashes tc = new TombstoneCrashes();
        byte[] data = readResourceBytes("android_data/tombstone_process.pb");
        tc.parse(new AbstractInput("FS/data/tombstones/tombstone_process.pb", new ByteArrayInputStream(data)) {});

        assertEquals(1, tc.getResults().size());

        @SuppressWarnings("unchecked")
        Map<String, Object> rec = (Map<String, Object>) tc.getResults().get(0);
        assertEquals("mtk.ape.decoder", rec.get("process_name"));
        assertEquals(25541, rec.get("pid"));
        assertEquals(1046, rec.get("uid"));
        assertEquals("/vendor/bin/hw/android.hardware.media.c2@1.2-mediatek",
                ((List<?>) rec.get("command_line")).get(0));
        assertEquals("2023-04-12 12:32:40.518290", rec.get("timestamp"));
    }

    @Test
    public void testCheckIndicators() throws Exception {
        TombstoneCrashes tc = new TombstoneCrashes();
        tc.setStringResolver(new JvmMapStringResolver());
        try (InputStream data = ResourcesUtils.readResource("android_data/tombstone_process.txt")) {
            tc.parse(new AbstractInput("tombstone_process", data) {});
        }

        Path dir = java.nio.file.Files.createTempDirectory("mvt-tombstone-iocs-");
        java.nio.file.Files.writeString(
                dir.resolve("iocs.json"),
                "{ \"indicators\": [ { \"process:name\": [ \"mtk.ape.decoder\" ] } ] }",
                java.nio.charset.StandardCharsets.UTF_8);
        Indicators indicators = new Indicators();
        indicators.loadFromDirectory(dir.toFile());
        tc.setIndicators(indicators);
        tc.checkIndicators();

        assertFalse(tc.detected.isEmpty());
        assertDetection(tc.detected, DetectionType.IOC_MATCH, AlertLevel.CRITICAL);
        assertDetectionValueContains(tc.detected, DetectionType.IOC_MATCH, "mtk.ape.decoder");
    }
}
