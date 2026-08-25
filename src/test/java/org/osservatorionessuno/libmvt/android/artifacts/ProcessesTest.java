package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;
import org.osservatorionessuno.libmvt.common.DetectionType;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionValueContains;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.loadTestIndicators;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.streamArtifact;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.streamRecords;

public class ProcessesTest {

    @Test
    public void testParsing() throws Exception {
        List<Object> parsed = streamRecords(
                Processes::new,
                "ps.txt",
                ResourcesUtils.readResource("android_data/ps.txt"));
        assertEquals(17, parsed.size());

        @SuppressWarnings("unchecked")
        Map<String, Object> first = (Map<String, Object>) parsed.get(0);
        assertEquals("init", first.get("proc_name"));
    }

    @Test
    public void testIocCheck() throws Exception {
        Processes p = streamArtifact(
                Processes::new,
                "ps.txt",
                ResourcesUtils.readResource("android_data/ps.txt"),
                loadTestIndicators());

        assertDetectionValueContains(p.detected, DetectionType.IOC_MATCH, "lru-add-drain");
    }

    @Test
    public void testTruncatedProcessMatch() throws Exception {
        String data = "USER PID PPID VSZ RSS WCHAN ADDR S NAME\n" +
                "root 50 2 0 0 0 0 S com.bad.actor.ma\n";
        Processes p = streamArtifact(
                Processes::new,
                "ps.txt",
                new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8)),
                loadTestIndicators());

        assertFalse(p.detected.isEmpty());
    }
}
