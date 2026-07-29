package org.osservatorionessuno.libmvt.android.artifacts;

import org.osservatorionessuno.libmvt.common.AbstractInput;
import org.osservatorionessuno.libmvt.common.Indicators.IndicatorType;

import java.util.*;
import java.io.IOException;

/** Parser for dumpsys battery history output. */
public class DumpsysBatteryHistory extends DumpsysArtifact {

    @Override
    public void parse(AbstractInput artifactInput) throws IOException {
        boolean[] done = { false };

        extractDumpsysSection(artifactInput.inputStream, "batterystats:", line -> {
            if (done[0]) return;
            if (line.startsWith("Battery History ")) return;
            if (line.trim().isEmpty()) {
                done[0] = true;
                return;
            }

            String trimmed = line.trim();
            String[] parts = trimmed.split(" ", 2);
            String timeElapsed = parts.length > 0 ? parts[0] : "";
            String event = "";
            String uid = "";
            String service = "";
            String packageName = "";

            if (line.contains("+job")) {
                event = "start_job";
                String[] job = parseJobEvent(line, "+job");
                if (job == null) return;
                uid = job[0];
                service = job[1];
                packageName = job[2];
            } else if (line.contains("-job")) {
                event = "end_job";
                String[] job = parseJobEvent(line, "-job");
                if (job == null) return;
                uid = job[0];
                service = job[1];
                packageName = job[2];
            } else if (line.contains("+running +wake_lock=")) {
                int start = line.indexOf("+running +wake_lock=") + 21;
                int colon = line.indexOf(':', start);
                if (colon < 0) return;
                uid = line.substring(start, colon);
                event = "wake";
                int walarm = line.indexOf("*walarm*:");
                if (walarm < 0) return;
                service = line.substring(walarm + 9).split(" ")[0].replace("\"", "").trim();
                if (service.isEmpty() || !service.contains("/")) return;
                packageName = service.split("/")[0];
            } else if (line.contains("+top=") || line.contains("-top")) {
                int topPos;
                if (line.contains("+top=")) {
                    event = "start_top";
                    topPos = line.indexOf("+top=");
                } else {
                    event = "end_top";
                    topPos = line.indexOf("-top");
                }
                int colon = line.indexOf(':', topPos);
                if (colon < 0) return;
                uid = line.substring(topPos + 5, colon);
                packageName = line.substring(colon + 1).replace("\"", "").trim();
            } else {
                return;
            }

            Map<String, String> map = new HashMap<>();
            map.put("time_elapsed", timeElapsed);
            map.put("event", event);
            map.put("uid", uid);
            map.put("package_name", packageName);
            map.put("service", service);
            emit(map);
        });
    }

    /*
        Parse a job event in the format: ... +job=u0a284:"org.telegram.messenger/.KeepAliveJob"
    */
    private static String[] parseJobEvent(String line, String marker) {
        int start = line.indexOf(marker) + marker.length() + 1;
        int colon = line.indexOf(':', start);
        if (colon < 0) return null;
        String uid = line.substring(start, colon);
        String service = line.substring(colon + 1).replace("\"", "").trim();
        String packageName = service.split("/")[0];
        return new String[] { uid, service, packageName };
    }

    @Override
    protected void checkRecord(Object record) {
        if (indicators == null) return;
        @SuppressWarnings("unchecked")
        Map<String, String> event = (Map<String, String>) record;
        detected.addAll(indicators.matchString(event.get("package_name"), IndicatorType.APP_ID));
    }
}
