package org.osservatorionessuno.libmvt.android.artifacts;

import org.osservatorionessuno.libmvt.common.AbstractInput;
import org.osservatorionessuno.libmvt.common.Detection;
import org.osservatorionessuno.libmvt.common.DetectionType;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.util.*;
import java.io.InputStream;
import java.io.IOException;

/** Parser for dumpsys adb output. */
public class DumpsysAdb extends DumpsysArtifact {

    private Set<String> hostFingerprints = Collections.emptySet();

    /**
     * Declare adb keys belonging to the acquiring host (adb_keys lines, e.g. from
     * adb_host_key.pub). Matching keys are reported as {@link DetectionType#ADB_HOST_FINGERPRINT}
     * instead of {@link DetectionType#ADB_FINGERPRINT}.
     */
    public void setHostKeys(Collection<String> keys) {
        Set<String> fingerprints = new HashSet<>();
        for (String key : keys) {
            String fingerprint = fingerprintOf(key);
            if (!fingerprint.isEmpty()) fingerprints.add(fingerprint);
        }
        hostFingerprints = fingerprints;
    }

    @Override
    public void parse(AbstractInput artifactInput) throws Exception {
        Map<String, Object> res = new HashMap<>();
        boolean[] inXml = {false};
        StringBuilder[] xmlBuilder = {null};
        Exception[] error = {null};

        extractDumpsysSection(artifactInput.inputStream, "adb:", rawLine -> {
            if (error[0] != null) return;
            try {
                String line = rawLine.trim();
                if (line.startsWith("user_keys=")) {
                    String val = line.substring(10).trim();
                    List<Map<String, String>> info = new ArrayList<>();
                    info.add(calculateKeyInfo(val));
                    res.put("user_keys", info);
                    return;
                }
                if (line.startsWith("keystore=")) {
                    String after = line.substring(9).trim();
                    if (after.startsWith("<?xml")) {
                        inXml[0] = true;
                        xmlBuilder[0] = new StringBuilder(after).append('\n');
                        if (after.contains("</keyStore>")) {
                            res.put("keystore", parseXml(xmlBuilder[0].toString()));
                            inXml[0] = false;
                            xmlBuilder[0] = null;
                        }
                    } else {
                        res.put("keystore", List.of(after));
                    }
                    return;
                }
                if (inXml[0] && xmlBuilder[0] != null) {
                    xmlBuilder[0].append(rawLine).append('\n');
                    if (rawLine.contains("</keyStore>")) {
                        res.put("keystore", parseXml(xmlBuilder[0].toString()));
                        inXml[0] = false;
                        xmlBuilder[0] = null;
                    }
                }
            } catch (Exception e) {
                error[0] = e;
            }
        });

        if (error[0] != null) throw error[0];
        // The whole section collapses into a single record: one keystore per device.
        emit(res);
    }

    private List<Map<String, String>> parseXml(String xml) throws Exception {
        var doc = DocumentBuilderFactory.newInstance().newDocumentBuilder()
                .parse(new ByteArrayInputStream(xml.getBytes()));
        List<Map<String, String>> list = new ArrayList<>();
        var nodes = doc.getElementsByTagName("adbKey");
        for (int i = 0; i < nodes.getLength(); i++) {
            var el = nodes.item(i);
            String key = el.getAttributes().getNamedItem("key").getNodeValue();
            Map<String, String> map = calculateKeyInfo(key);
            var lc = el.getAttributes().getNamedItem("lastConnection");
            if (lc != null) map.put("last_connected", lc.getNodeValue());
            list.add(map);
        }
        return list;
    }

    private Map<String, String> calculateKeyInfo(String userKey) {
        String keyBase64;
        String user = "";
        int space = userKey.indexOf(' ');
        if (space >= 0) {
            keyBase64 = userKey.substring(0, space);
            user = userKey.substring(space + 1);
        } else {
            keyBase64 = userKey;
        }
        Map<String, String> map = new HashMap<>();
        map.put("user", user);
        map.put("fingerprint", fingerprintOf(keyBase64));
        map.put("key", keyBase64);
        return map;
    }

    /**
     * MD5 colon-hex fingerprint of an adb public key, given either the base64 blob or a full
     * adb_keys line (base64 followed by a comment). Empty string if the key does not decode.
     */
    public static String fingerprintOf(String key) {
        String keyBase64 = key.trim();
        int space = keyBase64.indexOf(' ');
        if (space >= 0) keyBase64 = keyBase64.substring(0, space);
        try {
            byte[] raw = Base64.getDecoder().decode(keyBase64);
            // nosemgrep: java.lang.security.audit.crypto.use-of-md5.use-of-md5 - ADB fingerprints are legacy MD5 identifiers, not signatures.
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(raw);
            StringBuilder col = new StringBuilder();
            for (byte b : digest) {
                if (col.length() > 0) col.append(':');
                col.append(String.format("%02X", b));
            }
            return col.toString();
        } catch (IllegalArgumentException | java.security.NoSuchAlgorithmException e) {
            return "";
        }
    }

    @Override
    protected void checkRecord(Object record) {
        @SuppressWarnings("unchecked")
        Map<String, Object> adb = (Map<String, Object>) record;
        @SuppressWarnings("unchecked")
        List<Map<String, String>> userKeys = (List<Map<String, String>>) adb.get("user_keys");
        if (userKeys == null) return;

        for (Map<String, String> userKey : userKeys) {
            String fingerprint = userKey.get("fingerprint");
            DetectionType type = hostFingerprints.contains(fingerprint)
                ? DetectionType.ADB_HOST_FINGERPRINT
                : DetectionType.ADB_FINGERPRINT;
            detected.add(new Detection(type,
                fingerprint,
                userKey.get("user").isEmpty() ? "unknown user" : userKey.get("user")));
        }
    }
}
