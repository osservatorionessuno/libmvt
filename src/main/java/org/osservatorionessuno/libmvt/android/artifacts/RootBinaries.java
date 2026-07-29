package org.osservatorionessuno.libmvt.android.artifacts;

import org.json.JSONArray;
import org.json.JSONException;
import org.osservatorionessuno.libmvt.common.AbstractInput;
import org.osservatorionessuno.libmvt.common.Detection;
import org.osservatorionessuno.libmvt.common.DetectionType;
import org.osservatorionessuno.libmvt.common.Utils;
import org.osservatorionessuno.libmvt.android.ProtobufRecords;

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
        try {
            parseByExtension(artifactInput, this::parseProtobuf, this::parseJson);
        } catch (JSONException | IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    private void parseProtobuf(InputStream input) throws IOException {
        ProtobufRecords.forEachDelimited(input, record ->
                emit(ProtobufRecords.readStringRecord(record)));
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
