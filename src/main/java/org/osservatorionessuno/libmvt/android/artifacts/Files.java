package org.osservatorionessuno.libmvt.android.artifacts;

import org.json.JSONException;
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
import java.io.PushbackInputStream;
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
        return List.of("files.json", "files.jsonl");
    }

    @Override
    public void parse(AbstractInput artifactInput) throws IOException {
        try {
            parseByExtension(artifactInput, this::parseJson, this::parseJsonl);
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    private void parseJsonl(InputStream input) throws IOException {
        streamLines(input, true); // a malformed .jsonl line aborts the artifact
    }

    private void parseJson(InputStream input) throws IOException {
        // Peek the first non-whitespace byte: '{' is JSON-lines, which we stream since a real
        // device's files.json can be hundreds of MB; '[' is a JSON array (androidqf), read whole.
        PushbackInputStream in = new PushbackInputStream(new BufferedInputStream(input), 1);
        int b;
        do { b = in.read(); } while (b == ' ' || b == '\n' || b == '\r' || b == '\t');
        if (b == -1) return;
        in.unread(b);
        if (b == '{') {
            streamLines(in, false); // JSON-lines .json stays non-fatal on a bad line
        } else {
            parseJsonArray(in);
        }
    }

    private void streamLines(InputStream input, boolean abortOnError) throws IOException {
        forEachLine(input, line -> {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) return;
            try {
                emitObject(new JSONObject(trimmed));
            } catch (JSONException e) {
                if (abortOnError) throw new RuntimeException(e);
            }
        });
    }

    private void parseJsonArray(InputStream input) throws IOException {
        String content = collectText(input);
        try {
            JSONArray arr = new JSONArray(content);
            for (int i = 0; i < arr.length(); i++) emitObject(arr.getJSONObject(i));
        } catch (JSONException ex) {
            // Fallback: a non-array .json may still be JSON lines; skip invalid ones.
            for (String line : content.split("\\R")) {
                String trimmed = line.trim();
                if (trimmed.isEmpty()) continue;
                try {
                    emitObject(new JSONObject(trimmed));
                } catch (JSONException e2) {
                    // skip invalid lines
                }
            }
        }
    }

    private void emitObject(JSONObject obj) {
        Map<String, Object> map = new HashMap<>();
        Iterator<String> keys = obj.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            map.put(key, obj.opt(key));
        }
        emit(map);
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
