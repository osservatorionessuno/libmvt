package org.osservatorionessuno.libmvt.common;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;

import org.osservatorionessuno.libmvt.common.Indicators.IndicatorType;

import static org.junit.jupiter.api.Assertions.*;
import static org.osservatorionessuno.libmvt.common.Indicators.IndicatorType.*;

public class IndicatorsTest {

    private static final String SHA256 =
            "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
    private static final String SHA1 = "aabbccddeeff00112233445566778899aabbccdd";
    private static final String MD5 = "aabbccddeeff00112233445566778899";

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

    static Stream<Arguments> hashKeyVariants() {
        return Stream.of(
                Arguments.of("file:hashes.'SHA-256'", FILE_HASH_SHA256),
                Arguments.of("file:hashes.SHA-256", FILE_HASH_SHA256),
                Arguments.of("file:hashes.SHA256", FILE_HASH_SHA256),
                Arguments.of("file:hashes.sha256", FILE_HASH_SHA256),
                Arguments.of("file:hashes.'SHA-1'", FILE_HASH_SHA1),
                Arguments.of("file:hashes.SHA-1", FILE_HASH_SHA1),
                Arguments.of("file:hashes.SHA1", FILE_HASH_SHA1),
                Arguments.of("file:hashes.sha1", FILE_HASH_SHA1),
                Arguments.of("file:hashes.'MD5'", FILE_HASH_MD5),
                Arguments.of("file:hashes.MD5", FILE_HASH_MD5),
                Arguments.of("file:hashes.md5", FILE_HASH_MD5),
                Arguments.of("app:cert.'SHA-256'", APP_CERT_HASH_SHA256),
                Arguments.of("app:cert.SHA-256", APP_CERT_HASH_SHA256),
                Arguments.of("app:cert.SHA256", APP_CERT_HASH_SHA256),
                Arguments.of("app:cert.sha256", APP_CERT_HASH_SHA256),
                Arguments.of("app:cert.'SHA-1'", APP_CERT_HASH_SHA1),
                Arguments.of("app:cert.SHA-1", APP_CERT_HASH_SHA1),
                Arguments.of("app:cert.sha1", APP_CERT_HASH_SHA1),
                Arguments.of("app:cert.'MD5'", APP_CERT_HASH_MD5),
                Arguments.of("app:cert.md5", APP_CERT_HASH_MD5),
                Arguments.of("domain-name:value", DOMAIN)
        );
    }

    @ParameterizedTest
    @MethodSource("hashKeyVariants")
    public void typeForKey_normalisesHashAlgorithms(String key, IndicatorType expected) {
        assertEquals(expected, Indicators.typeForKey(key));
    }

    @Test
    public void specQuotedSha256PatternIsLoaded() throws Exception {
        Indicators indicators = load("spec.stix2", stixPattern("file:hashes.'SHA-256'", SHA256));
        assertFalse(indicators.matchString(SHA256, FILE_HASH_SHA256).isEmpty());
    }

    @Test
    public void unquotedHyphenatedSha256PatternIsLoaded() throws Exception {
        Indicators indicators = load("hyphen.stix2", stixPattern("file:hashes.SHA-256", SHA256));
        assertFalse(indicators.matchString(SHA256, FILE_HASH_SHA256).isEmpty());
    }

    @Test
    public void compactSha256PatternIsLoaded() throws Exception {
        Indicators indicators = load("compact.stix2", stixPattern("file:hashes.SHA256", SHA256));
        assertFalse(indicators.matchString(SHA256, FILE_HASH_SHA256).isEmpty());
    }

    @Test
    public void lowercaseSha256PatternStillLoads() throws Exception {
        Indicators indicators = load("lower.stix2", stixPattern("file:hashes.sha256", SHA256));
        assertFalse(indicators.matchString(SHA256, FILE_HASH_SHA256).isEmpty());
    }

    @Test
    public void specQuotedSha1AndMd5PatternsAreLoaded() throws Exception {
        Indicators sha1 = load("sha1.stix2", stixPattern("file:hashes.'SHA-1'", SHA1));
        assertFalse(sha1.matchString(SHA1, FILE_HASH_SHA1).isEmpty());
        Indicators md5 = load("md5.stix2", stixPattern("file:hashes.'MD5'", MD5));
        assertFalse(md5.matchString(MD5, FILE_HASH_MD5).isEmpty());
    }

    @Test
    public void specQuotedAppCertSha256PatternIsLoaded() throws Exception {
        Indicators indicators = load("cert.stix2", stixPattern("app:cert.'SHA-256'", SHA256));
        assertFalse(indicators.matchString(SHA256, APP_CERT_HASH_SHA256).isEmpty());
    }

    @Test
    public void mvtStyleQuotedHashKeyIsLoaded() throws Exception {
        String mvt = "{\"indicators\": [{\"file:hashes.'SHA-256'\": [\"" + SHA256 + "\"]}]}";
        Indicators indicators = load("mvt-hash.json", mvt);
        assertFalse(indicators.matchString(SHA256, FILE_HASH_SHA256).isEmpty());
    }

    @Test
    public void stixRelationshipAttributesMalwareFamily() throws Exception {
        Indicators indicators = load("predator.stix2", STIX_WITH_RELATIONSHIP);
        List<Detection> detections = indicators.matchString("shortenurls.me", DOMAIN);
        assertEquals(1, detections.size());
        assertEquals(List.of("Predator", "DOMAIN", "shortenurls.me"), detections.get(0).getValue());
    }

    @Test
    public void mvtStyleMatchHasEmptyMalwareFamily() throws Exception {
        String mvt = "{\"indicators\": [{\"domain-name:value\": [\"bad.example\"]}]}";
        Indicators indicators = load("mvt.json", mvt);
        List<Detection> detections = indicators.matchString("dns query for bad.example", DOMAIN);
        assertEquals(1, detections.size());
        assertEquals(List.of("", "DOMAIN", "dns query for bad.example"), detections.get(0).getValue());
    }

    @Test
    public void stixFileLevelMalwareFallback() throws Exception {
        Indicators indicators = load("family.stix2", STIX_WITHOUT_RELATIONSHIP);
        List<Detection> detections = indicators.matchString("implant.apk", FILE_NAME);
        assertEquals(1, detections.size());
        assertEquals(List.of("Pegasus", "FILE_NAME", "implant.apk"), detections.get(0).getValue());
    }

    @Test
    public void processIocDoesNotMatchInsideUnderscoreToken() throws Exception {
        Indicators indicators = load("proc.stix2", stixPattern("process:name", "bh"));
        assertTrue(indicators.matchString("rcu_bh", PROCESS).isEmpty());
    }

    @Test
    public void processIocMatchesExactName() throws Exception {
        Indicators indicators = load("proc.stix2", stixPattern("process:name", "bh"));
        List<Detection> detections = indicators.matchString("bh", PROCESS);
        assertEquals(1, detections.size());
        assertEquals(List.of("", "PROCESS", "bh"), detections.get(0).getValue());
    }

    @Test
    public void processIocMatchesHyphenatedName() throws Exception {
        Indicators indicators = load("proc.stix2", stixPattern("process:name", "lru-add-drain"));
        assertFalse(indicators.matchString("lru-add-drain", PROCESS).isEmpty());
    }

    @Test
    public void processIocMatchesTruncatedCommName() throws Exception {
        Indicators indicators = load("proc.stix2", stixPattern("process:name", "com.bad.actor.malware"));
        assertFalse(indicators.matchString("com.bad.actor.ma", PROCESS).isEmpty());
        assertFalse(indicators.matchString("com.bad.actor.m", PROCESS).isEmpty());
    }

    @Test
    public void domainIocStillMatchesInsideSentence() throws Exception {
        Indicators indicators = load("dom.stix2", stixPattern("domain-name:value", "evil.example"));
        assertFalse(indicators.matchString("connecting to evil.example now", DOMAIN).isEmpty());
    }

    @Test
    public void appIdIocDoesNotMatchLongerPackage() throws Exception {
        Indicators indicators = load("app.stix2", stixPattern("app:id", "com.foo"));
        assertTrue(indicators.matchString("com.foo.bar", APP_ID).isEmpty());
        assertFalse(indicators.matchString("com.foo", APP_ID).isEmpty());
    }

    private static final String STIX_WITH_RELATIONSHIP =
            "{\"type\":\"bundle\",\"objects\":["
            + "{\"type\":\"malware\",\"id\":\"malware--1\",\"name\":\"Predator\"},"
            + "{\"type\":\"indicator\",\"id\":\"indicator--1\",\"pattern\":\"[domain-name:value='shortenurls.me']\"},"
            + "{\"type\":\"relationship\",\"relationship_type\":\"indicates\","
            + "\"source_ref\":\"indicator--1\",\"target_ref\":\"malware--1\"}"
            + "]}";

    private static final String STIX_WITHOUT_RELATIONSHIP =
            "{\"type\":\"bundle\",\"objects\":["
            + "{\"type\":\"malware\",\"id\":\"malware--1\",\"name\":\"Pegasus\"},"
            + "{\"type\":\"indicator\",\"id\":\"indicator--1\",\"pattern\":\"[file:name = 'implant.apk']\"}"
            + "]}";

    private static String stixPattern(String key, String value) {
        return "{\"objects\":[{\"type\":\"indicator\",\"pattern\":\"[" + key + " = '" + value + "']\"}]}";
    }

    private static int indexOfByte(byte[] bytes, byte value) {
        for (int i = 0; i < bytes.length; i++) {
            if (bytes[i] == value) return i;
        }
        return -1;
    }
}
