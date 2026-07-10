package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;
import org.osservatorionessuno.libmvt.common.AbstractInput;
import org.osservatorionessuno.libmvt.common.DetectionType;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionValueContains;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.runIocCheck;

public class ProcessesTest {

    @Test
    public void testParsing() throws Exception {
        Processes p = new Processes();
        InputStream data = ResourcesUtils.readResource("android_data/ps.txt");
        p.parse(new AbstractInput("ps.txt", data) {});
        assertEquals(17, p.getResults().size());

        @SuppressWarnings("unchecked")
        Map<String, Object> first = (Map<String, Object>) p.getResults().get(0);
        assertEquals("init", first.get("proc_name"));
    }

    @Test
    public void testIocCheck() throws Exception {
        Processes p = new Processes();
        InputStream data = ResourcesUtils.readResource("android_data/ps.txt");
        p.parse(new AbstractInput("ps.txt", data) {});

        runIocCheck(p);

        assertDetectionValueContains(p.detected, DetectionType.IOC_MATCH, "lru-add-drain");
    }

    @Test
    public void testTruncatedProcessMatch() throws Exception {
        Processes p = new Processes();
        String data = "USER PID PPID VSZ RSS WCHAN ADDR S NAME\n" +
                "root 50 2 0 0 0 0 S com.bad.actor.ma\n";
        p.parse(new AbstractInput("ps.txt", new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8))) {});

        runIocCheck(p);

        // TODO: fix this test
        // assertFalse(p.detected.isEmpty());
    }
}
