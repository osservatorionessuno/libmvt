package org.osservatorionessuno.libmvt.android.artifacts;

import org.osservatorionessuno.libmvt.common.AbstractInput;
import org.osservatorionessuno.libmvt.common.Detection;
import org.osservatorionessuno.libmvt.common.DetectionType;
import org.osservatorionessuno.libmvt.common.Indicators.IndicatorType;

import java.util.*;
import java.io.IOException;

/** Parser for dumpsys receivers information. */
public class DumpsysReceivers extends AndroidArtifact {

    @Override
    public List<String> paths() {
        return List.of("dumpsys.txt", "bugreport-*.txt");
    }

    @Override
    public void parse(AbstractInput artifactInput) throws IOException {
        results.clear();
        boolean[] inTable = { false };
        boolean[] inNonData = { false };
        boolean[] done = { false };
        String[] currentIntent = { null };

        extractDumpsysSection(artifactInput.inputStream, "package:", line -> {
            if (done[0]) return;
            if (line.startsWith("Receiver Resolver Table:")) {
                inTable[0] = true;
                return;
            }
            if (!inTable[0]) return;
            if (line.startsWith("  Non-Data Actions:")) {
                inNonData[0] = true;
                return;
            }
            if (!inNonData[0]) return;
            if (line.trim().isEmpty()) {
                done[0] = true;
                return;
            }
            if (line.startsWith("     ") && !line.startsWith("        ") && line.contains(":")) {
                currentIntent[0] = line.trim().replace(":", "");
                return;
            }
            if (currentIntent[0] == null) return;
            if (!line.startsWith("        ")) {
                currentIntent[0] = null;
                return;
            }
            String receiver = line.trim().split(" ")[1];
            String pkg = receiver.split("/")[0];
            Map<String, String> rec = new HashMap<>();
            rec.put("intent", currentIntent[0]);
            rec.put("package_name", pkg);
            rec.put("receiver", receiver);
            results.add(rec);
        });
    }

    @Override
    public void checkIndicators() {
        if (results.isEmpty()) return;

        for (Object obj : results) {
            @SuppressWarnings("unchecked")
            Map<String, String> map = (Map<String, String>) obj;

            String intent = map.get("intent");
            String receiver = map.get("receiver");
            switch (Objects.requireNonNull(intent)) {
                case "android.provider.Telephony.NEW_OUTGOING_SMS":
                    detected.add(new Detection(DetectionType.DUMPSYS_RECEIVERS_OUTGOING_SMS, receiver));
                    break;
                case "android.provider.Telephony.SMS_RECEIVED":
                    detected.add(new Detection(DetectionType.DUMPSYS_RECEIVERS_INCOMING_SMS, receiver));
                    break;
                case "android.intent.action.DATA_SMS_RECEIVED":
                    detected.add(new Detection(DetectionType.DUMPSYS_RECEIVERS_DATA_SMS, receiver));
                    break;
                case "android.intent.action.PHONE_STATE":
                    detected.add(new Detection(DetectionType.DUMPSYS_RECEIVERS_PHONE_STATE, receiver));
                    break;
                case "android.intent.action.NEW_OUTGOING_CALL":
                    detected.add(new Detection(DetectionType.DUMPSYS_RECEIVERS_OUTGOING_CALL, receiver));
                    break;
            }

            if (indicators == null) continue;
            String pkg = map.get("package_name");
            detected.addAll(indicators.matchString(pkg, IndicatorType.APP_ID));
        }
    }
}
