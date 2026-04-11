package org.osservatorionessuno.libmvt.common;

import org.junit.jupiter.api.Test;

import java.io.BufferedWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.List;

import org.osservatorionessuno.libmvt.common.Indicators.IndicatorType;

import static org.junit.jupiter.api.Assertions.*;

public class IndicatorsUpdatesTest {

    @Test
    public void testUpdateLocal() throws Exception {
        Path temp = Files.createTempDirectory("mvt");

        Path stix = Paths.get("src", "test", "resources", "stix2", "cytrox.stix2");
        String index =
                "indicators:\n" +
                        "  - name: local\n" +
                        "    type: url\n" +
                        "    url: " + stix.toUri().toString() + "\n";

        Path indexFile = Files.createTempFile(temp, "index", ".yaml");
        try (BufferedWriter bw = Files.newBufferedWriter(indexFile, StandardCharsets.UTF_8,
                StandardOpenOption.TRUNCATE_EXISTING)) {
            bw.write(index);
        }

        IndicatorsUpdates updates = new IndicatorsUpdates(temp, List.of(indexFile.toUri().toString()));
        updates.update();

        Path indicatorsDir = temp.resolve("iocs");
        // Match IndicatorsUpdates' filename logic: replace only http(s) scheme and slash/backslash with '_'
        String fileName = stix.toUri().toString()
                .replaceFirst("^https?://", "")
                .replaceAll("[/\\\\]", "_");
        assertTrue(Files.exists(indicatorsDir.resolve(fileName)));

        Indicators indicators = new Indicators();
        indicators.loadFromDirectory(indicatorsDir.toFile());
        assertFalse(indicators.matchString("shortenurls.me", IndicatorType.DOMAIN).isEmpty());
    }

    @Test
    public void testUpdateFromUrl() throws Exception {
        Path temp = Files.createTempDirectory("mvt");

        String stix = "https://raw.githubusercontent.com/mvt-project/mvt-indicators/refs/heads/main/cellebrite/cellebrite.stix2";
        String index =
                "indicators:\n" +
                        "  - name: url\n" +
                        "    type: url\n" +
                        "    url: https://raw.githubusercontent.com/mvt-project/mvt-indicators/refs/heads/main/cellebrite/cellebrite.stix2\n";

        Path indexFile = Files.createTempFile(temp, "index", ".yaml");
        try (BufferedWriter bw = Files.newBufferedWriter(indexFile, StandardCharsets.UTF_8,
                StandardOpenOption.TRUNCATE_EXISTING)) {
            bw.write(index);
        }

        IndicatorsUpdates updates = new IndicatorsUpdates(temp, List.of(indexFile.toUri().toString()));
        updates.update();

        Path indicatorsDir = temp.resolve("iocs");
        // Match IndicatorsUpdates' filename logic: replace only http(s) scheme and slash/backslash with '_'
        String fileName = stix
                .replaceFirst("^https?://", "")
                .replaceAll("[/\\\\]", "_");

        assertTrue(Files.exists(indicatorsDir.resolve(fileName)));

        Indicators indicators = new Indicators();
        indicators.loadFromDirectory(indicatorsDir.toFile());
        assertFalse(indicators.matchString("com.client.appA", IndicatorType.APP_ID).isEmpty());
    }
}
