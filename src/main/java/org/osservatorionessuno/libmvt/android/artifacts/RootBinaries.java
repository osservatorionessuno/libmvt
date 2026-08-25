package org.osservatorionessuno.libmvt.android.artifacts;

import org.json.JSONArray;
import org.json.JSONException;
import org.osservatorionessuno.libmvt.common.AbstractInput;
import org.osservatorionessuno.libmvt.common.Detection;
import org.osservatorionessuno.libmvt.common.DetectionType;
import org.osservatorionessuno.libmvt.common.Utils;

import java.util.List;
import java.io.BufferedInputStream;
import java.io.InputStream;
import java.io.IOException;

/**
 * TODO
 */
public class RootBinaries extends AndroidArtifact {
    @Override
    public List<String> paths() {
        return List.of("root_binaries.json", "root_binaries.jsonl");
    }

    @Override
    public void parse(AbstractInput artifactInput) throws IOException, JSONException {
        try {
            parseByExtension(artifactInput, this::parseJson, this::parseJsonl);
        } catch (JSONException | IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    private void parseJsonl(InputStream input) throws IOException {
        // Stream one JSON string (path) per line; a malformed line aborts the artifact.
        forEachLine(input, line -> {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) return;
            try {
                String path = (String) new org.json.JSONTokener(trimmed).nextValue();
                if (path != null && !path.isEmpty()) emit(path);
            } catch (JSONException | ClassCastException e) {
                throw new RuntimeException(e);
            }
        });
    }

    private void parseJson(InputStream input) throws IOException, JSONException {
        String content = collectText(input);
        if (content == null || content.trim().isEmpty()) {
            return;
        }
        JSONArray entries = new JSONArray(content);
        for (int idx = 0; idx < entries.length(); idx++) {
            emit(entries.getString(idx));
        }
    }

    @Override
    protected void checkRecord(Object record) {
        String path = (String) record;
        if (path == null || path.trim().isEmpty()) return;

        // Extract binary name from path
        String[] parts = path.replace("\\", "/").split("/");
        String binaryName = parts[parts.length - 1].toLowerCase();

        // If a description is found, than the binary is known, otherwise it is unknown.
        String description = Utils.ROOT_BINARIES.get(binaryName);
        if (description == null) {
            description = "unknown root file";
        }

        detected.add(new Detection(DetectionType.ROOT_BINARIES, path, description));
    }
}
