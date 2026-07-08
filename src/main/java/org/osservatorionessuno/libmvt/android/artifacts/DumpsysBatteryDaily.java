package org.osservatorionessuno.libmvt.android.artifacts;

import org.osservatorionessuno.libmvt.common.AbstractInput;
import org.osservatorionessuno.libmvt.common.Indicators.IndicatorType;

import java.util.*;
import java.io.IOException;

/** Parser for dumpsys battery daily output. */
public class DumpsysBatteryDaily extends AndroidArtifact {

    @Override
    public List<String> paths() {
        return List.of("dumpsys.txt", "bugreport-*.txt");
    }

    @Override
    public void parse(AbstractInput artifactInput) throws IOException {
        results.clear();
        Map<String, String>[] daily = new Map[] { null };
        boolean[] inPackageChanges = { false };
        List<Map<String, String>> updates = new ArrayList<>();

        extractDumpsysSection(artifactInput.inputStream, "batterystats:", line -> {
            if (line.startsWith("  Daily from ")) {
                if (!updates.isEmpty()) {
                    results.addAll(updates);
                    updates.clear();
                }
                String tf = line.substring(13).trim();
                String[] parts = tf.replace(":", "").split(" to ", 2);
                if (parts.length < 2) {
                    daily[0] = null;
                    inPackageChanges[0] = false;
                    return;
                }
                daily[0] = new HashMap<>();
                daily[0].put("from", parts[0].substring(0, 10));
                daily[0].put("to", parts[1].substring(0, 10));
                inPackageChanges[0] = false;
                return;
            }
            if (daily[0] == null) return;
            if ("Package changes:".equals(line.trim())) {
                inPackageChanges[0] = true;
                return;
            }
            if (!inPackageChanges[0]) return;
            String trimmed = line.trim();
            if (!trimmed.startsWith("Update ")) return;
            trimmed = trimmed.substring(7);
            int versIdx = trimmed.indexOf(" vers=");
            if (versIdx < 0) return;
            String pkg = trimmed.substring(0, versIdx).trim();
            String vers = trimmed.substring(versIdx + " vers=".length()).trim();
            if (pkg.isEmpty() || vers.isEmpty()) return;
            boolean exists = false;
            for (Map<String, String> u : updates) {
                if (u.get("package_name").equals(pkg) && u.get("vers").equals(vers)) {
                    exists = true;
                    break;
                }
            }
            if (!exists) {
                Map<String, String> rec = new HashMap<>();
                rec.put("action", "update");
                rec.put("from", daily[0].get("from"));
                rec.put("to", daily[0].get("to"));
                rec.put("package_name", pkg);
                rec.put("vers", vers);
                updates.add(rec);
            }
        });
        if (!updates.isEmpty()) results.addAll(updates);
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
