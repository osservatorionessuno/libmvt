package org.osservatorionessuno.libmvt.android.artifacts;

import org.osservatorionessuno.libmvt.common.AbstractInput;
import org.osservatorionessuno.libmvt.common.Detection;
import org.osservatorionessuno.libmvt.common.DetectionType;
import org.osservatorionessuno.libmvt.common.Indicators.IndicatorType;

import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;
import java.util.Set;
import org.json.JSONArray;
import java.io.BufferedInputStream;
import java.io.InputStream;
import java.io.IOException;

/**
 * Parser for the output of the `mount` command.
 */
public class Mounts extends AndroidArtifact {
    private static final Set<String> SUSPICIOUS_MOUNT_POINTS = Set.of("/system", "/vendor", "/product", "/system_ext");
    private static final Set<String> SUSPICIOUS_OPTIONS = Set.of("rw", "remount", "noatime", "nodiratime");
    private static final Set<String> ALLOWLIST_NOATIME = Set.of("/system_dlkm", "/system_ext", "/product", "/vendor", "/vendor_dlkm");

    @Override
    public List<String> paths() {
        return List.of("mounts.json", "mounts.jsonl");
    }

    @Override
    public void parse(AbstractInput artifactInput) throws IOException {
        try {
            parseByExtension(artifactInput, this::parseJson, this::parseJsonl);
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    private void parseJson(InputStream input) throws IOException {
        // Expect input as a JSON string representing an array of mount entry lines (not direct file lines).
        String content = collectText(input);
        if (content == null || content.trim().isEmpty()) {
            return;
        }
        try {
            JSONArray entries = new JSONArray(content);

            for (int idx = 0; idx < entries.length(); idx++) {
                String entry = entries.getString(idx);
                if (entry == null || entry.trim().isEmpty()) {
                    continue;
                }

                Map<String, Object> mountEntry = parseMountEntry(entry);
                if (mountEntry != null) {
                    emit(mountEntry);
                }
            }
        } catch (Exception ex) {
            // If malformed JSON or unexpected error - skip all
            // TODO: maybe report a better error message (?)
            return;
        }
        return;
    }

    private void parseJsonl(InputStream input) throws IOException {
        // Stream one JSON string (raw mount line) per line; a malformed line aborts the artifact.
        forEachLine(input, line -> {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) return;
            try {
                String entry = (String) new org.json.JSONTokener(trimmed).nextValue();
                Map<String, Object> mount = parseMountEntry(entry);
                if (mount != null) emit(mount);
            } catch (org.json.JSONException | ClassCastException e) {
                throw new RuntimeException(e);
            }
        });
    }

    private Map<String, Object> parseMountEntry(String entry) {
        String device = null;
        String mountPoint = null;
        String filesystemType = null;
        String mountOptions = "";

        if (!entry.contains(" on ") || !entry.contains(" type ")) {
            // Skip lines that don't match the expected format
            return null;
        }

        try {
            String[] deviceSplit = entry.split(" on ", 2);
            device = deviceSplit[0].trim();
            String rest = deviceSplit[1];

            String[] mountAndFsSplit = rest.split(" type ", 2);
            mountPoint = mountAndFsSplit[0].trim();
            String fsPart = mountAndFsSplit[1];

            if (fsPart.contains("(") && fsPart.endsWith(")")) {
                int parenIdx = fsPart.indexOf('(');
                filesystemType = fsPart.substring(0, parenIdx).trim();
                mountOptions = fsPart.substring(parenIdx + 1, fsPart.length() - 1).trim();
            } else {
                filesystemType = fsPart.trim();
                mountOptions = "";
            }

            if (device.isEmpty() || mountPoint.isEmpty() || filesystemType.isEmpty()) {
                return null;
            }

            String[] optionsArray = mountOptions.isEmpty() ? new String[0] : mountOptions.split(",");
            List<String> optionsList = new ArrayList<>();
            for (String opt : optionsArray) {
                String trimmed = opt.trim();
                if (!trimmed.isEmpty()) {
                    optionsList.add(trimmed);
                }
            }

            boolean isSystemPartition = isSuspiciousMountPoint(mountPoint);
            boolean isReadWrite = optionsList.contains("rw");

            Map<String,Object> mountEntry = new HashMap<>();
            mountEntry.put("device", device);
            mountEntry.put("mount_point", mountPoint);
            mountEntry.put("filesystem_type", filesystemType);
            mountEntry.put("mount_options", mountOptions);
            mountEntry.put("options_list", optionsList);
            mountEntry.put("is_system_partition", isSystemPartition);
            mountEntry.put("is_read_write", isReadWrite);

            return mountEntry;
        } catch (Exception e) {
            // parsing failed, skip this line
            return null;
        }
    }

    private boolean isSuspiciousMountPoint(String mountPoint) {
        return SUSPICIOUS_MOUNT_POINTS.contains(mountPoint)
                || SUSPICIOUS_MOUNT_POINTS.stream().anyMatch(mountPoint::startsWith);
    }

    @Override
    protected void checkRecord(Object record) {
        @SuppressWarnings("unchecked")
        Map<String, Object> mount = (Map<String, Object>) record;
        checkMountOptions(mount);

        // Check indicators if available
        if (indicators == null) return;

        // Check if any mount points match indicators
        String mp = (String) mount.get("mount_point");
        detected.addAll(indicators.matchString(mp, IndicatorType.FILE_PATH));

        // Check device paths for indicators
        String dev = (String) mount.get("device");
        detected.addAll(indicators.matchString(dev, IndicatorType.FILE_PATH));
    }

    private void checkMountOptions(Map<String, Object> mount) {
        String mountPoint = (String) mount.get("mount_point");
        @SuppressWarnings("unchecked")
        List<String> options = (List<String>) mount.get("options_list");

        // Check for system partitions mounted as read-write
        if (Boolean.TRUE.equals(mount.get("is_system_partition")) && Boolean.TRUE.equals(mount.get("is_read_write"))) {
            detected.add(new Detection(DetectionType.MOUNTS_SYSTEM, mountPoint));
        }

        // Check for other suspicious mount options
        List<String> suspiciousOpts = new ArrayList<>();
        for (String opt : options) {
            if (SUSPICIOUS_OPTIONS.contains(opt)) {
                suspiciousOpts.add(opt);
            }
        }
        if (!suspiciousOpts.isEmpty() && Boolean.TRUE.equals(mount.get("is_system_partition"))) {
            // ALLOWLIST_NOATIME handling: skip allowed case
            String mountOptions = (String) mount.get("mount_options");
            if (mountOptions != null && mountOptions.contains("noatime")
                && ALLOWLIST_NOATIME.contains(mountPoint)) {
                return;
            }
            detected.add(new Detection(DetectionType.MOUNTS_SUSPICIOUS,
                mountPoint, String.join(", ", suspiciousOpts)));
        }

        // Log interesting mount information (just log - map to LOG detection)
        if ("/data".equals(mountPoint) || mountPoint.startsWith("/sdcard")) {
            detected.add(new Detection(DetectionType.MOUNTS_DATA,
                mountPoint,
                String.valueOf(mount.get("filesystem_type")),
                String.valueOf(mount.get("mount_options"))));
        }
    }
}
