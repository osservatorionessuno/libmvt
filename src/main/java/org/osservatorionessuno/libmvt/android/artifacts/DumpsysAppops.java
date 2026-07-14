package org.osservatorionessuno.libmvt.android.artifacts;

import org.osservatorionessuno.libmvt.common.AbstractInput;
import org.osservatorionessuno.libmvt.common.Detection;
import org.osservatorionessuno.libmvt.common.DetectionType;
import org.osservatorionessuno.libmvt.common.Indicators.IndicatorType;

import java.util.*;
import java.io.IOException;
import java.io.InputStream;

/** Parser for dumpsys appops output. */
public class DumpsysAppops extends DumpsysArtifact {
    private static final Set<String> RISKY_PERMISSIONS = Set.of("REQUEST_INSTALL_PACKAGES");
    private static final Set<String> RISKY_PACKAGES = Set.of("com.android.shell");

    @Override
    public void parse(AbstractInput artifactInput) throws IOException {
        results.clear();
        Map<String, Object>[] pkg = new Map[] { null };
        Map<String, Object>[] perm = new Map[] { new HashMap<>() };
        Map<String, Object>[] entry = new Map[] { new HashMap<>() };
        String[] uid = { null };
        boolean[] inPackages = { false };
        boolean[] done = { false };

        extractDumpsysSection(artifactInput.inputStream, "appops:", line -> {
            if (done[0]) return;
            if (line.startsWith("  Uid 0:")) inPackages[0] = true;
            if (!inPackages[0]) return;
            if (line.startsWith("  Uid ")) {
                uid[0] = line.substring(6, line.length() - 1);
                if (!entry[0].isEmpty()) { addEntry(perm[0], entry[0]); entry[0] = new HashMap<>(); }
                if (pkg[0] != null) {
                    finishPerm(pkg[0], perm[0]);
                    results.add(pkg[0]);
                }
                pkg[0] = null;
                perm[0] = new HashMap<>();
                return;
            }
            if (line.startsWith("    Package ")) {
                if (!entry[0].isEmpty()) { addEntry(perm[0], entry[0]); entry[0] = new HashMap<>(); }
                if (pkg[0] != null) {
                    finishPerm(pkg[0], perm[0]);
                    results.add(pkg[0]);
                }
                pkg[0] = new HashMap<>();
                pkg[0].put("package_name", line.substring(12, line.length() - 1));
                pkg[0].put("permissions", new ArrayList<>());
                pkg[0].put("uid", uid[0]);
                perm[0] = new HashMap<>();
                return;
            }
            if (pkg[0] != null && line.startsWith("      ") && line.length() > 6 && line.charAt(6) != ' ') {
                if (!entry[0].isEmpty()) { addEntry(perm[0], entry[0]); entry[0] = new HashMap<>(); }
                finishPerm(pkg[0], perm[0]);
                perm[0] = new HashMap<>();
                String[] parts = line.trim().split("\\s+");
                perm[0].put("name", parts[0]);
                perm[0].put("entries", new ArrayList<>());
                if (parts.length > 1) perm[0].put("access", parts[1].substring(1, parts[1].length() - 2));
                return;
            }
            if (line.startsWith("          ")) {
                String access = line.split(":")[0].trim();
                if (!access.equals("Access") && !access.equals("Reject")) return;
                if (!entry[0].isEmpty()) { addEntry(perm[0], entry[0]); entry[0] = new HashMap<>(); }
                entry[0].put("access", access);
                int l = line.indexOf('[');
                int r = line.indexOf(']');
                if (l > 0 && r > l) entry[0].put("type", line.substring(l + 1, r));
                int lp = line.indexOf(']', r) + 1;
                int lp2 = line.indexOf('(', lp);
                if (lp > 0 && lp2 > lp) {
                    String ts = line.substring(lp, lp2).trim();
                    entry[0].put("timestamp", ts);
                }
                return;
            }
            if (line.trim().isEmpty()) done[0] = true;
        });
        if (!entry[0].isEmpty()) addEntry(perm[0], entry[0]);
        finishPerm(pkg[0], perm[0]);
        if (pkg[0] != null) results.add(pkg[0]);
    }

    @SuppressWarnings("unchecked")
    private void addEntry(Map<String, Object> perm, Map<String, Object> entry) {
        ((List<Object>) perm.computeIfAbsent("entries", k -> new ArrayList<>())).add(entry);
    }

    @SuppressWarnings("unchecked")
    private void finishPerm(Map<String, Object> pkg, Map<String, Object> perm) {
        if (pkg != null && !perm.isEmpty()) {
            ((List<Object>) pkg.get("permissions")).add(perm);
        }
    }

    @Override
    public void checkIndicators() {
        if (indicators == null) return;
        for (Object obj : results) {
            @SuppressWarnings("unchecked")
            Map<String, Object> map = (Map<String, Object>) obj;
            String pkgName = (String) map.get("package_name");
            detected.addAll(indicators.matchString(pkgName, IndicatorType.APP_ID));
            
            boolean riskyPkg = RISKY_PACKAGES.contains(pkgName);
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> perms = (List<Map<String, Object>>) map.get("permissions");
            if (perms == null) continue;
            
            for (Map<String, Object> perm : perms) {
                String permName = (String) perm.get("name");
                if (RISKY_PERMISSIONS.contains(permName) || riskyPkg) {
                    detected.add(new Detection(DetectionType.APPOPS_RISKY_PERMISSION,
                        pkgName,
                        permName,
                        String.valueOf(perm.get("access")),
                        String.valueOf(perm.get("timestamp"))));
                }
            }
        }
    }
}
