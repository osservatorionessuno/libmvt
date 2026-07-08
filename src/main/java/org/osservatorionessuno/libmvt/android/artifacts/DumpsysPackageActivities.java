package org.osservatorionessuno.libmvt.android.artifacts;

import org.osservatorionessuno.libmvt.common.AbstractInput;
import org.osservatorionessuno.libmvt.common.Indicators.IndicatorType;

import java.util.*;
import java.io.IOException;

/** Parser for dumpsys packages activities output. */
public class DumpsysPackageActivities extends AndroidArtifact {

    @Override
    public List<String> paths() {
        return List.of("dumpsys.txt", "bugreport-*.txt");
    }

    @Override
    public void parse(AbstractInput artifactInput) throws IOException {
        results.clear();
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
            results.add(record);
        });
    }

    @Override
    public void checkIndicators() {
        if (indicators == null) return;
        for (Object obj : results) {
            @SuppressWarnings("unchecked")
            Map<String, String> rec = (Map<String, String>) obj;
            detected.addAll(indicators.matchString(rec.get("package_name"), IndicatorType.APP_ID));
        }
    }
}
