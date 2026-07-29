package org.osservatorionessuno.libmvt.android.artifacts;

import org.osservatorionessuno.libmvt.common.AbstractInput;
import org.osservatorionessuno.libmvt.common.Detection;
import org.osservatorionessuno.libmvt.common.DetectionType;
import org.osservatorionessuno.libmvt.common.Indicators.IndicatorType;
import org.osservatorionessuno.libmvt.common.Utils;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.io.IOException;
import java.io.InputStream;

/**
 * Parser for dumpsys package information.
 */
public class DumpsysPackages extends DumpsysArtifact {

    private static final Pattern PACKAGE_RX = Pattern.compile("  Package \\[(.+?)\\].*");

    private static class PackageDetails {
        String packageName = "";
        String uid = "";
        String versionName = "";
        String versionCode = "";
        String timestamp = "";
        String firstInstall = "";
        String lastUpdate = "";
        List<Map<String, Object>> permissions = new ArrayList<>();
        List<String> requestedPermissions = new ArrayList<>();
    }

    private static Map<String, Object> toMap(PackageDetails d) {
        Map<String, Object> m = new HashMap<>();
        m.put("package_name", d.packageName);
        m.put("uid", d.uid);
        m.put("version_name", d.versionName);
        m.put("version_code", d.versionCode);
        m.put("timestamp", d.timestamp);
        m.put("first_install_time", d.firstInstall);
        m.put("last_update_time", d.lastUpdate);
        m.put("permissions", d.permissions);
        m.put("requested_permissions", d.requestedPermissions);
        return m;
    }

    private static Map<String, Object> parsePermissionLine(String line, String type) {
        String[] lineinfo = line.trim().split(":", 2);
        String permission = lineinfo[0];
        Boolean granted = null;
        if (lineinfo.length > 1 && lineinfo[1].contains("granted=")) {
            granted = lineinfo[1].contains("granted=true");
        }
        Map<String, Object> p = new HashMap<>();
        p.put("name", permission);
        p.put("granted", granted);
        p.put("type", type);
        return p;
    }

    static PackageDetails parsePackageBlock(List<String> lines) {
        PackageDetails d = new PackageDetails();
        boolean inInstall = false, inRuntime = false, inDeclared = false, inRequested = true;
        for (String line : lines) {
            if (inInstall) {
                if (line.startsWith("    ") && !line.startsWith("      ")) {
                    inInstall = false;
                } else {
                    Map<String, Object> p = parsePermissionLine(line, "install");
                    d.permissions.add(p);
                    continue;
                }
            }
            if (inRuntime) {
                if (!line.startsWith("        ")) {
                    inRuntime = false;
                } else {
                    Map<String, Object> p = parsePermissionLine(line, "runtime");
                    d.permissions.add(p);
                    continue;
                }
            }
            if (inDeclared) {
                if (!line.startsWith("      ")) {
                    inDeclared = false;
                } else {
                    String permission = line.trim().split(":")[0];
                    Map<String, Object> p = new HashMap<>();
                    p.put("name", permission);
                    p.put("type", "declared");
                    d.permissions.add(p);
                    continue;
                }
            }
            if (inRequested) {
                if (!line.startsWith("      ")) {
                    inRequested = false;
                } else {
                    d.requestedPermissions.add(line.trim());
                    continue;
                }
            }
            line = line.trim();
            if (line.startsWith("userId=")) d.uid = line.substring(7).trim();
            else if (line.startsWith("versionName=")) d.versionName = line.substring(12).trim();
            else if (line.startsWith("versionCode=")) d.versionCode = line.substring(12).trim();
            else if (line.startsWith("timeStamp=")) d.timestamp = line.substring(10).trim();
            else if (line.startsWith("firstInstallTime=")) d.firstInstall = line.substring(17).trim();
            else if (line.startsWith("lastUpdateTime=")) d.lastUpdate = line.substring(15).trim();
            else if (line.equals("install permissions:")) inInstall = true;
            else if (line.equals("runtime permissions:")) inRuntime = true;
            else if (line.equals("declared permissions:")) inDeclared = true;
            else if (line.equals("requested permissions:")) inRequested = true;
        }
        return d;
    }

    @Override
    public void parse(AbstractInput artifactInput) throws IOException {
        boolean[] inPackageList = { false };
        boolean[] done = { false };
        String[] packageName = { null };
        // Only the block being read is buffered, never the whole package list.
        List<String> block = new ArrayList<>();

        extractDumpsysSection(artifactInput.inputStream, "package:", line -> {
            if (done[0]) return;
            if (line.startsWith("Packages:")) {
                inPackageList[0] = true;
                return;
            }
            if (!inPackageList[0]) return;
            if (line.trim().isEmpty()) {
                done[0] = true;
                return;
            }
            if (line.startsWith("  Package [")) {
                // A block ends where the next one starts, so the previous package flushes here.
                emitPackage(packageName[0], block);
                Matcher m = PACKAGE_RX.matcher(line);
                packageName[0] = m.find() ? m.group(1) : null;
                return;
            }
            if (packageName[0] != null) block.add(line);
        });
        emitPackage(packageName[0], block);
    }

    private void emitPackage(String packageName, List<String> block) {
        if (packageName != null && !block.isEmpty()) {
            PackageDetails details = parsePackageBlock(block);
            details.packageName = packageName;
            emit(toMap(details));
        }
        block.clear();
    }

    @Override
    protected void checkRecord(Object record) {
        @SuppressWarnings("unchecked")
        Map<String, Object> pkg = (Map<String, Object>) record;
        String name = (String) pkg.get("package_name");
        if (Utils.ROOT_PACKAGES.contains(name)) {
            detected.add(new Detection(DetectionType.PACKAGES_ROOT_PACKAGE, name));
            return;
        }
        if (indicators != null) {
            detected.addAll(indicators.matchString(name, IndicatorType.APP_ID));
        }
    }
}
