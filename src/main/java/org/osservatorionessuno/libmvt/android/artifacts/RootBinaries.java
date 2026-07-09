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
        return List.of("root_binaries.pb", "root_binaries.json");
    }

    @Override
    public void parse(AbstractInput artifactInput) throws IOException, JSONException {
        results.clear();
        if (artifactInput.path.endsWith(".pb")) {
            parseProtobuf(artifactInput.inputStream);
            return;
        } else if (artifactInput.path.endsWith(".json")) {
            parseJson(artifactInput.inputStream);
            return;
        }
        throw new IOException("Unsupported file type: " + artifactInput.path);
    }

    private void parseProtobuf(InputStream input) throws IOException {
        byte[] record;
        while ((record = ProtobufRecords.readDelimited(input)) != null) {
            results.add(ProtobufRecords.readStringRecord(record));
        }
    }

    private void parseJson(InputStream input) throws IOException, JSONException {
        String content = collectText(input);
        if (content == null || content.trim().isEmpty()) {
            return;
        }
        JSONArray entries = new JSONArray(content);
        for (int idx = 0; idx < entries.length(); idx++) {
            results.add(entries.getString(idx));
        }
    }

    @Override
    public void checkIndicators() {
        for (Object obj : results) {
            @SuppressWarnings("unchecked")
            String path = (String) obj;
            if (path == null || path.trim().isEmpty()) continue;

            // Extract binary name from path
            String[] parts = path.replace("\\", "/").split("/");
            String binaryName = parts[parts.length - 1].toLowerCase();

            // If a description is found, than the binary is known, otherwise it is unknown.
            String description = Utils.ROOT_BINARIES.get(binaryName);
            if (description == null) {
                description = "unknown root file";
            }

            detected.add(new Detection(DetectionType.ROOT_BINARIES, description, path));
        }
    }
}
