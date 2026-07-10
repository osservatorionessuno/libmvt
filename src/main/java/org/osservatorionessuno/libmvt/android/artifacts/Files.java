package org.osservatorionessuno.libmvt.android.artifacts;

import com.google.protobuf.CodedInputStream;
import org.json.JSONException;
import org.osservatorionessuno.libmvt.android.ProtobufRecords;
import org.osservatorionessuno.libmvt.common.AbstractInput;
import org.osservatorionessuno.libmvt.common.Detection;
import org.osservatorionessuno.libmvt.common.DetectionType;
import org.osservatorionessuno.libmvt.common.Indicators.IndicatorType;

import java.util.List;
import java.util.HashMap;
import java.util.Map;
import java.util.Iterator;
import java.util.Objects;
import java.util.Set;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Parser for the list of all the files available on the devices
 */
public class Files extends AndroidArtifact {
    private static final Set<String> SUSPICIOUS_PATHS = Set.of(
        "/data/local/tmp/"
    );

    @Override
    public List<String> paths() {
        return List.of("files.pb", "files.json");
    }

    @Override
    public void parse(AbstractInput artifactInput) throws IOException {
        results.clear();
        try {
            parseByExtension(artifactInput, this::parseProtobuf, this::parseJson);
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    private void parseProtobuf(InputStream input) throws IOException {
        ProtobufRecords.forEachDelimited(input, record -> {
            CodedInputStream codedInput = CodedInputStream.newInstance(record);
            Map<String, Object> file = parseFileRecord(codedInput);
            results.add(file);
        });
    }

    private Map<String, Object> parseFileRecord(CodedInputStream input) throws IOException {
        Map<String, Object> map = new HashMap<>();
        int tag;
        while ((tag = input.readTag()) != 0) {
            switch (tag >>> 3) {
                case 1 -> map.put("path", ProtobufRecords.readString(input));
                case 2 -> map.put("mtime", input.readDouble());
                case 3 -> map.put("mode", ProtobufRecords.readString(input));
                case 4 -> map.put("size", input.readInt64());
                case 5 -> map.put("user", ProtobufRecords.readString(input));
                case 6 -> map.put("group", ProtobufRecords.readString(input));
                default -> input.skipField(tag);
            }
        }
        return map;
    }

    private void parseJson(InputStream input) throws IOException {
        try {
            // Try to parse the input as a JSON array
            JSONArray arr = new JSONArray(collectText(input));
            for (int i = 0; i < arr.length(); i++) {
                JSONObject obj = arr.getJSONObject(i);
                Map<String, Object> map = new HashMap<>();
                Iterator<String> keys = obj.keys();
                while (keys.hasNext()) {
                    String key = keys.next();
                    map.put(key, obj.get(key));
                }
                results.add(map);
            }
        } catch (JSONException ex) {
            // Fallback: input may be JSON lines, one object per line
            // TODO: I think this wont work cause Text was already collected.
            for (String line : collectLines(input)) {
                String trimmed = line.trim();
                if (trimmed.isEmpty()) continue;
                try {
                    JSONObject obj = new JSONObject(trimmed);
                    Map<String, Object> map = new HashMap<>();
                    Iterator<String> keys = obj.keys();
                    while (keys.hasNext()) {
                        String key = keys.next();
                        map.put(key, obj.get(key));
                    }
                    // Again, no conversion of timestamps; assume preprocessed
                    results.add(map);
                } catch (JSONException e2) {
                    // skip invalid lines
                    // TODO: maybe report a better error message (?)
                }
            }
        }
    }

    @Override
    public void checkIndicators() {
        if (indicators == null) return;

        for (Object obj : results) {
            @SuppressWarnings("unchecked")
            Map<String, Object> file = (Map<String, Object>) obj;

            String path = Objects.toString(file.get("path"), "");
            if (path.isEmpty()) continue;

            if (detected.addAll(indicators.matchString(path, IndicatorType.FILE_PATH))) {
                continue; // if any indicator matches, skip the rest
            }

            for (String suspicious : SUSPICIOUS_PATHS) {
                if (path.startsWith(suspicious)) {
                    String fileType = "";

                    // Determine if the file is executable (Unix mode bits)
                    Object modeVal = file.get("mode");
                    long mode = 0;
                    if (modeVal instanceof Number) {
                        mode = ((Number) modeVal).longValue();
                    } else if (modeVal instanceof String) {
                        try {
                            mode = Long.decode("0" + (String) modeVal);
                        } catch (NumberFormatException nfe) {
                            // ignore
                        }
                    }
                    // executable for owner, group, or others (octal 0100, 0010, 0001)
                    if ((mode & 0111) != 0) { // (S_IXUSR | S_IXGRP | S_IXOTH)
                        fileType = "executable ";
                    }

                    detected.add(new Detection(DetectionType.FILES_SUSPICIOUS_PATH, fileType, path));
                }
            }
 
            Object sha256Obj = file.get("sha256");
            String sha256 = (sha256Obj != null) ? sha256Obj.toString() : "";
            if (sha256.isEmpty()) continue;

            // Check if file hash matches any indicator
            detected.addAll(indicators.matchString(sha256, IndicatorType.FILE_HASH_SHA256));

            // TODO: add SHA1 and MD5 check when available
        }
    }
}
