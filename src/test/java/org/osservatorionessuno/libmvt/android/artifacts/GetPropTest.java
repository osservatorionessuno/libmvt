package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;
import org.osservatorionessuno.libmvt.common.AbstractInput;
import org.osservatorionessuno.libmvt.common.Indicators;

import java.io.InputStream;
import java.nio.file.Paths;
import java.util.Map;

import org.osservatorionessuno.libmvt.common.DetectionType;

import static org.junit.jupiter.api.Assertions.*;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionValueContains;

public class GetPropTest {

    @Test
    public void testParsing() throws Exception {
        GetProp gp = new GetProp();
        InputStream data = ResourcesUtils.readResource("android_data/getprop.txt");
        gp.parse(new AbstractInput("getprop.txt", data) {});
        assertEquals(13, gp.getResults().size());

        @SuppressWarnings("unchecked")
        Map<String, String> first = (Map<String, String>) gp.getResults().get(0);
        assertEquals("af.fast_track_multiplier", first.get("name"));
        assertEquals("1", first.get("value"));
    }

    @Test
    public void testIocCheck() throws Exception {
        GetProp gp = new GetProp();
        InputStream data = ResourcesUtils.readResource("android_data/getprop.txt");
        gp.parse(new AbstractInput("getprop.txt", data) {});

        Indicators indicators = new Indicators();
        indicators.loadFromDirectory(
                Paths.get("src", "test", "resources", "iocs").toFile()
        );
        gp.setIndicators(indicators);
        gp.checkIndicators();

        assertDetectionValueContains(gp.detected, DetectionType.IOC_MATCH, "dalvik.vm.appimageformat");
    }
}
