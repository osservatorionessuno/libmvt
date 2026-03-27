package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;
import org.osservatorionessuno.libmvt.common.Indicators;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class ProcessesTest {

    @Test
    public void testParsing() throws Exception {
        Processes p = new Processes();
        InputStream data = ResourcesUtils.readResource("android_data/ps.txt");
        p.parse(data);
        assertEquals(17, p.getResults().size());

        @SuppressWarnings("unchecked")
        Map<String, Object> first = (Map<String, Object>) p.getResults().get(0);
        assertEquals("init", first.get("proc_name"));
    }

    @Test
    public void testIocCheck() throws Exception {
        Processes p = new Processes();
        InputStream data = ResourcesUtils.readResource("android_data/ps.txt");
        p.parse(data);

        Indicators indicators = new Indicators();
        indicators.loadFromDirectory(
                Paths.get("src", "test", "resources", "iocs").toFile()
        );
        p.setIndicators(indicators);
        p.checkIndicators();

        assertTrue(p.detected.size() > 0);
    }

    @Test
    public void testTruncatedProcessMatch() throws Exception {
        Processes p = new Processes();
        String data = "USER PID PPID VSZ RSS WCHAN ADDR S NAME\n" +
                "root 50 2 0 0 0 0 S com.bad.actor.ma\n";
        p.parse(new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8)));

        Indicators indicators = new Indicators();
        indicators.loadFromDirectory(
                Paths.get("src", "test", "resources", "iocs").toFile()
        );
        p.setIndicators(indicators);
        p.checkIndicators();

        // TODO: fix this test
        // assertFalse(p.detected.isEmpty());
    }
}
