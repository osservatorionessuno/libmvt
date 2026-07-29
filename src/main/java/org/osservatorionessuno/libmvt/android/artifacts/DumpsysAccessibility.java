package org.osservatorionessuno.libmvt.android.artifacts;

import org.osservatorionessuno.libmvt.common.AbstractInput;
import org.osservatorionessuno.libmvt.common.Indicators.IndicatorType;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.io.InputStream;
import java.io.IOException;

public class DumpsysAccessibility extends DumpsysArtifact {

    @Override
    public void parse(AbstractInput artifactInput) throws IOException {
        Pattern legacyPattern = Pattern.compile("\\s*(\\d+) : (.+)");
        Pattern v14Pattern = Pattern.compile("\\{\\{(.+?)\\}\\}", Pattern.DOTALL);
        boolean[] inLegacyBlock = {false};
        boolean[] inV14Search = {false};

        extractDumpsysSection(artifactInput.inputStream, "accessibility:", line -> {
            String trimmed = line.trim();
            if (trimmed.startsWith("installed services:")) {
                inLegacyBlock[0] = true;
                inV14Search[0] = false;
                return;
            }
            if (inLegacyBlock[0]) {
                if (trimmed.startsWith("}")) {
                    inLegacyBlock[0] = false;
                    return;
                }
                Matcher m = legacyPattern.matcher(line);
                if (m.find()) {
                    String fullService = m.group(2).trim();
                    String packageName = fullService.split("/")[0];
                    Map<String, String> result = new HashMap<>();
                    result.put("package_name", packageName);
                    result.put("service", fullService);
                    emit(result);
                }
                return;
            }
            if (trimmed.startsWith("Enabled services:")) {
                inV14Search[0] = true;
            }
            if (inV14Search[0]) {
                Matcher m = v14Pattern.matcher(line);
                if (m.find()) {
                    String fullService = m.group(1).trim();
                    String[] parts = fullService.split("/");
                    String packageName = parts[0];
                    String service = parts.length > 1 ? parts[1] : "";
                    Map<String, String> result = new HashMap<>();
                    result.put("package_name", packageName);
                    result.put("service", service.isEmpty() ? fullService : service);
                    emit(result);
                    inV14Search[0] = false;
                }
            }
        });
    }

    @Override
    protected void checkRecord(Object record) {
        if (indicators == null) return;
        @SuppressWarnings("unchecked")
        Map<String, String> service = (Map<String, String>) record;
        detected.addAll(indicators.matchString(service.get("package_name"), IndicatorType.APP_ID));
    }
}