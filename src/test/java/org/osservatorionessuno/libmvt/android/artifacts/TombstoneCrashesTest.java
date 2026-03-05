package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;

import java.io.InputStream;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.osservatorionessuno.libmvt.ResourcesUtils.readResourceBytes;

public class TombstoneCrashesTest {

    @Test
    public void testParsing() throws Exception {
        TombstoneCrashes tc = new TombstoneCrashes();
        InputStream data = ResourcesUtils.readResource("android_data/tombstone_process.txt");
        tc.parse(data);

        System.out.printf("Parsed text tombstone, results: %d%n", tc.getResults().size());
        for (Object r : tc.getResults()) {
            System.out.println("Parsed record (text): " + r);
        }

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
        byte[] data = ResourcesUtils.readResourceBytes("android_data/tombstone_process.pb");
        tc.parseProtobuf(data);

        System.out.printf("Parsed protobuf tombstone, results: %d%n", tc.getResults().size());
        for (Object r : tc.getResults()) {
            System.out.println("Parsed record (protobuf): " + r);
        }

        if (tc.getResults().isEmpty()) return;
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
    @Disabled("Not implemented yet")
    public void testParseKernel() throws Exception {
        // Skipped: kernel tombstone parsing is not yet implemented
    }
}
