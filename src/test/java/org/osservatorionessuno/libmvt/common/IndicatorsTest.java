package org.osservatorionessuno.libmvt.common;

import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.osservatorionessuno.libmvt.common.Indicators.IndicatorType;

import static org.junit.jupiter.api.Assertions.*;

public class IndicatorsTest {

    private static final String NDJSON_BUNDLE =
            "{\"id\":\"bundle--test\",\"objects\":[\n"
            + "{\"id\":\"indicator--1\",\"pattern\":\"[domain-name:value = 'evil.example']\",\"type\":\"indicator\"},\n"
            + "{\"id\":\"indicator--2\",\"pattern\":\"[file:name = 'implant.apk']\",\"type\":\"indicator\"}\n"
            + "],\"type\":\"bundle\"}\n";

    private static final String PRETTY_BUNDLE =
            "{\n"
            + "  \"id\": \"bundle--test\",\n"
            + "  \"type\": \"bundle\",\n"
            + "  \"objects\": [\n"
            + "    {\n"
            + "      \"id\": \"indicator--1\",\n"
            + "      \"type\": \"indicator\",\n"
            + "      \"pattern\": \"[domain-name:value = 'evil.example']\"\n"
            + "    }\n"
            + "  ]\n"
            + "}\n";

    private Indicators load(String name, String content) throws Exception {
        Path dir = Files.createTempDirectory("mvt-indicators");
        Files.write(dir.resolve(name), content.getBytes(StandardCharsets.UTF_8));
        Indicators indicators = new Indicators();
        indicators.loadFromDirectory(dir.toFile());
        return indicators;
    }

    @Test
    public void loadsLinePerObjectBundle() throws Exception {
        // The layout the bugbane update feed emits.
        Indicators indicators = load("bundle.json", NDJSON_BUNDLE);
        assertFalse(indicators.matchString("connecting to evil.example now", IndicatorType.DOMAIN).isEmpty());
        assertFalse(indicators.matchString("implant.apk", IndicatorType.FILE_NAME).isEmpty());
        assertTrue(indicators.matchString("innocuous.example", IndicatorType.DOMAIN).isEmpty());
    }

    @Test
    public void prettyPrintedBundleParsesIdentically() throws Exception {
        // Same indicators, arbitrary layout: the pull parser is layout-agnostic.
        Indicators indicators = load("pretty.stix2", PRETTY_BUNDLE);
        assertFalse(indicators.matchString("connecting to evil.example now", IndicatorType.DOMAIN).isEmpty());
    }

    @Test
    public void minifiedSingleLineBundleParsesIdentically() throws Exception {
        Indicators indicators = load("minified.json", NDJSON_BUNDLE.replace("\n", ""));
        assertFalse(indicators.matchString("connecting to evil.example now", IndicatorType.DOMAIN).isEmpty());
    }

    @Test
    public void mvtStyleFileStillLoads() throws Exception {
        String mvt = "{\"indicators\": [{\"domain-name:value\": [\"bad.example\"]}]}";
        Indicators indicators = load("mvt.json", mvt);
        assertFalse(indicators.matchString("dns query for bad.example", IndicatorType.DOMAIN).isEmpty());
    }

    @Test
    public void multiByteUtf8SurvivesChunkBoundaries() throws Exception {
        // Position a two-byte UTF-8 character ('é', 0xC3 0xA9) so it straddles the 4096-byte
        // boundary: the previous loader decoded fixed-size byte chunks independently, which
        // corrupted it (silently breaking that indicator); a character stream does not.
        String head = "{\n  \"objects\": [\n    {\"type\": \"indicator\", \"id\": \"indicator--";
        String tail = "\", \"pattern\": \"[domain-name:value = 'évil.example']\"}\n  ]\n}\n";
        int bytesBeforePattern = head.getBytes(StandardCharsets.UTF_8).length;
        int bytesFromIdEndToE = "\", \"pattern\": \"[domain-name:value = '".getBytes(StandardCharsets.UTF_8).length;
        // pad the id so the first byte of 'é' lands at offset 4095
        int pad = 4095 - bytesBeforePattern - bytesFromIdEndToE;
        StringBuilder id = new StringBuilder();
        for (int i = 0; i < pad; i++) id.append('x');
        String bundle = head + id + tail;
        assertEquals(4095, indexOfByte(bundle.getBytes(StandardCharsets.UTF_8), (byte) 0xC3));

        Indicators indicators = load("boundary.stix2", bundle);
        assertFalse(indicators.matchString("visit évil.example today", IndicatorType.DOMAIN).isEmpty());
    }

    private static int indexOfByte(byte[] bytes, byte value) {
        for (int i = 0; i < bytes.length; i++) {
            if (bytes[i] == value) return i;
        }
        return -1;
    }
}
