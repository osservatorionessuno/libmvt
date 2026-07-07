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
public class DumpsysAdb extends AndroidArtifact {
    private static final Set<String> MULTILINE = Set.of("user_keys", "keystore");

    @Override
    public List<String> paths() {
        return List.of("dumpsys.txt", "bugreport-*.txt");
    }

    @Override
    public void parse(AbstractInput artifactInput) throws Exception {
        results.clear();
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
        results.add(res);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> cast(Object o) {
        return (Map<String, Object>) o;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> indentedDumpParser(String data) {
        Map<String, Object> root = new HashMap<>();
        Deque<Object> stack = new ArrayDeque<>();
        stack.push(root);
        int curIndent = 0;
        boolean inMultiline = false;
        for (String rawLine : data.split("\n")) {
            String line = rawLine.replaceAll("\r", "");
            int indent = line.length() - line.stripLeading().length();
            if (indent < curIndent) {
                while (curIndent > indent && stack.size() > 1) {
                    stack.pop();
                    curIndent -= 2;
                }
                curIndent = indent;
            } else {
                curIndent = indent;
            }
            String[] parts = line.stripLeading().split("=", 2);
            String key = parts[0];
            Object current = stack.peek();
            if (inMultiline) {
                if (key.isEmpty()) {
                    inMultiline = false;
                    stack.pop();
                } else {
                    ((List<String>) current).add(line.strip());
                }
                continue;
            }
            if (key.equals("}")) { stack.pop(); continue; }
            String value = parts.length > 1 ? parts[1] : "";
            if ("{".equals(value)) {
                Map<String, Object> map = new HashMap<>();
                ((Map<String, Object>) current).put(key, map);
                stack.push(map);
            } else if (MULTILINE.contains(key)) {
                List<String> list = new ArrayList<>();
                list.add(value);
                ((Map<String, Object>) current).put(key, list);
                stack.push(list);
                inMultiline = true;
            } else {
                ((Map<String, Object>) current).put(key, value);
            }
        }
        return root;
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

    private Map<String, String> calculateKeyInfo(String userKey) throws Exception {
        String keyBase64;
        String user = "";
        int space = userKey.indexOf(' ');
        if (space >= 0) {
            keyBase64 = userKey.substring(0, space);
            user = userKey.substring(space + 1);
        } else {
            keyBase64 = userKey;
        }
        String fingerprint = "";
        try {
            byte[] raw = Base64.getDecoder().decode(keyBase64);
            // nosemgrep: java.lang.security.audit.crypto.use-of-md5.use-of-md5 - ADB fingerprints are legacy MD5 identifiers, not signatures.
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(raw);
            StringBuilder hex = new StringBuilder();
            for (byte b : digest) hex.append(String.format("%02X", b));
            StringBuilder col = new StringBuilder();
            for (int i = 0; i < hex.length(); i += 2) {
                if (i > 0) col.append(':');
                col.append(hex.substring(i, i + 2));
            }
            fingerprint = col.toString();
        } catch (IllegalArgumentException e) {
            fingerprint = "";
        }
        Map<String, String> map = new HashMap<>();
        map.put("user", user);
        map.put("fingerprint", fingerprint);
        map.put("key", keyBase64);
        return map;
    }

    @Override
    public void checkIndicators() {
        if (results.isEmpty()) return;

        for (Object obj : results) {
            @SuppressWarnings("unchecked")
            Map<String, Object> map = (Map<String, Object>) obj;
            @SuppressWarnings("unchecked")
            List<Map<String, String>> userKeys = (List<Map<String, String>>) map.get("user_keys");
            if (userKeys != null) {
                for (Map<String, String> userKey : userKeys) {
                    detected.add(new Detection(DetectionType.ADB_FINGERPRINT,
                        userKey.get("user"),
                        userKey.get("fingerprint")));
                }
            }
        }
    }
}
