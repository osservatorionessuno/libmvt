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
            emit(parseFileRecord(codedInput));
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
        // Read once: collectText closes the stream, so the fallback below reuses the text.
        String content = collectText(input);
        try {
            // Try to parse the input as a JSON array
            JSONArray arr = new JSONArray(content);
            for (int i = 0; i < arr.length(); i++) {
                JSONObject obj = arr.getJSONObject(i);
                Map<String, Object> map = new HashMap<>();
                Iterator<String> keys = obj.keys();
                while (keys.hasNext()) {
                    String key = keys.next();
                    map.put(key, obj.get(key));
                }
                emit(map);
            }
        } catch (JSONException ex) {
            // Fallback: input may be JSON lines, one object per line
            for (String line : content.split("\\R")) {
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
                    emit(map);
                } catch (JSONException e2) {
                    // skip invalid lines
                    // TODO: maybe report a better error message (?)
                }
            }
        }
    }

    @Override
    protected void checkRecord(Object record) {
        @SuppressWarnings("unchecked")
        Map<String, Object> file = (Map<String, Object>) record;

        String path = Objects.toString(file.get("path"), "");
        if (path.isEmpty()) return;

        if (indicators != null
                && detected.addAll(indicators.matchString(path, IndicatorType.FILE_PATH))) {
            return; // if any indicator matches, skip the rest
        }

        for (String suspicious : SUSPICIOUS_PATHS) {
            if (path.startsWith(suspicious)) {
                String fileType = isExecutable(file.get("mode")) ? "executable " : "";
                detected.add(new Detection(DetectionType.FILES_SUSPICIOUS_PATH, path, fileType));
            }
        }

        if (indicators == null) return;

        Object sha256Obj = file.get("sha256");
        String sha256 = (sha256Obj != null) ? sha256Obj.toString() : "";
        if (sha256.isEmpty()) return;

        // Check if file hash matches any indicator
        detected.addAll(indicators.matchString(sha256, IndicatorType.FILE_HASH_SHA256));
    }

    /**
     * True if any of the owner, group or other execute bits are set.
     *
     * <p>Producers disagree on the encoding: {@code find -printf '%m'} yields octal digits
     * ("755"), while androidqf's collector yields a symbolic string ("-rwxr-xr-x"). Devices
     * whose find lacks -printf supply no mode at all.
     */
    private static boolean isExecutable(Object modeVal) {
        if (modeVal instanceof Number) {
            return (((Number) modeVal).longValue() & 0111) != 0;
        }
        if (!(modeVal instanceof String)) return false;

        String mode = ((String) modeVal).trim();
        if (mode.isEmpty()) return false;

        if (isOctalDigits(mode)) {
            try {
                return (Long.parseLong(mode, 8) & 0111) != 0;
            } catch (NumberFormatException nfe) {
                return false;
            }
        }

        // Symbolic: an optional leading file-type char then three rwx triads. A lowercase x
        // is plain execute; s and t are setuid/setgid/sticky *with* execute, whereas the
        // uppercase forms mean the bit is set without it.
        String bits = (mode.length() == 10) ? mode.substring(1) : mode;
        if (bits.length() != 9) return false;
        for (int i = 2; i < 9; i += 3) {
            char c = bits.charAt(i);
            if (c == 'x' || c == 's' || c == 't') return true;
        }
        return false;
    }

    private static boolean isOctalDigits(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < '0' || c > '7') return false;
        }
        return true;
    }
}
