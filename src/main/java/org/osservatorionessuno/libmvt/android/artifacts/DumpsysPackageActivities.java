package org.osservatorionessuno.libmvt.android.artifacts;

import org.osservatorionessuno.libmvt.common.AbstractInput;
import org.osservatorionessuno.libmvt.common.Indicators.IndicatorType;

import java.util.*;
import java.io.IOException;

/** Parser for dumpsys packages activities output. */
public class DumpsysPackageActivities extends DumpsysArtifact {

    @Override
    public void parse(AbstractInput artifactInput) throws IOException {
        boolean[] inActivityResolver = { false };
        boolean[] inNonDataActions = { false };
        boolean[] done = { false };
        String[] intent = { null };

        extractDumpsysSection(artifactInput.inputStream, "package:", line -> {
            if (done[0]) return;
            if (line.startsWith("Activity Resolver Table:")) {
                inActivityResolver[0] = true;
                return;
            }
            if (!inActivityResolver[0]) return;
            if (line.startsWith("  Non-Data Actions:")) {
                inNonDataActions[0] = true;
                return;
            }
            if (!inNonDataActions[0]) return;
            if (line.trim().isEmpty()) {
                done[0] = true;
                return;
            }
            if (line.startsWith("      ") && !line.startsWith("        ") && line.contains(":")) {
                intent[0] = line.trim().replace(":", "");
                return;
            }
            if (intent[0] == null) return;
            if (!line.startsWith("        ")) {
                intent[0] = null;
                return;
            }
            String[] parts = line.trim().split(" ");
            if (parts.length < 2) return;
            String activity = parts[1];
            String packageName = activity.split("/")[0];
            Map<String, String> record = new HashMap<>();
            record.put("intent", intent[0]);
            record.put("package_name", packageName);
            record.put("activity", activity);
            emit(record);
        });
    }

    @Override
    protected void checkRecord(Object record) {
        if (indicators == null) return;
        @SuppressWarnings("unchecked")
        Map<String, String> activity = (Map<String, String>) record;
        detected.addAll(indicators.matchString(activity.get("package_name"), IndicatorType.APP_ID));
    }
}
