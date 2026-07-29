package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;
import org.osservatorionessuno.libmvt.common.DetectionType;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionValueContains;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.indicatorsFromJson;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.loadTestIndicators;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.streamArtifact;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.streamRecords;

public class GetPropTest {

    @Test
    public void testParsing() throws Exception {
        List<Object> parsed = streamRecords(
                GetProp::new,
                "getprop.txt",
                ResourcesUtils.readResource("android_data/getprop.txt"));
        assertEquals(13, parsed.size());

        @SuppressWarnings("unchecked")
        Map<String, String> first = (Map<String, String>) parsed.get(0);
        assertEquals("af.fast_track_multiplier", first.get("name"));
        assertEquals("1", first.get("value"));
    }

    @Test
    public void testIocCheck() throws Exception {
        GetProp gp = streamArtifact(
                GetProp::new,
                "getprop.txt",
                ResourcesUtils.readResource("android_data/getprop.txt"),
                loadTestIndicators());

        assertDetectionValueContains(gp.detected, DetectionType.IOC_MATCH, "dalvik.vm.appimageformat");
    }

    /**
     * A property gets its own heuristic AND its IOC match: the security-patch check must not
     * consume the record and suppress the PROPERTY match.
     */
    @Test
    public void testSecurityPatchPropertyIsStillIocMatched() throws Exception {
        String props = "[ro.build.version.security_patch]: [2019-01-01]\n";
        GetProp gp = streamArtifact(
                GetProp::new,
                "getprop.txt",
                new ByteArrayInputStream(props.getBytes(StandardCharsets.UTF_8)),
                indicatorsFromJson(
                        "{ \"indicators\": [ { \"android-property:name\": "
                                + "[ \"ro.build.version.security_patch\" ] } ] }"));

        assertDetectionValueContains(
                gp.detected, DetectionType.GETPROP_SECURITY_PATCH, "2019-01-01");
        assertDetectionValueContains(
                gp.detected, DetectionType.IOC_MATCH, "ro.build.version.security_patch");
    }

    /** The timezone is kept from the stream, since the records themselves are dropped. */
    @Test
    public void testDeviceTimezoneSurvivesStreaming() throws Exception {
        String props = "[ro.product.locale]: [en-GB]\n[persist.sys.timezone]: [Europe/Rome]\n";
        GetProp gp = streamArtifact(
                GetProp::new,
                "getprop.txt",
                new ByteArrayInputStream(props.getBytes(StandardCharsets.UTF_8)));

        assertEquals("Europe/Rome", gp.getDeviceTimezone());
    }
}
