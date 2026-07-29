package org.osservatorionessuno.libmvt.android.artifacts;

import org.osservatorionessuno.libmvt.common.AbstractInput;
import org.osservatorionessuno.libmvt.common.Detection;
import org.osservatorionessuno.libmvt.common.DetectionType;
import org.osservatorionessuno.libmvt.common.Indicators.IndicatorType;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.io.IOException;
import java.io.InputStream;

/**
 * Parser for the output of the `getprop` command.
 */
public class GetProp extends AndroidArtifact {
    private static final Pattern PATTERN = Pattern.compile("\\[(.+?)\\]: \\[(.*?)\\]");
    private static final Set<String> INTERESTING_PROPERTIES = Set.of(
        "gsm.sim.operator.alpha",
        "gsm.sim.operator.iso-country",
        "persist.sys.timezone",
        "ro.boot.serialno",
        "ro.build.version.sdk",
        "ro.build.version.security_patch",
        "ro.product.cpu.abi",
        "ro.product.locale",
        "ro.product.vendor.manufacturer",
        "ro.product.vendor.model",
        "ro.product.vendor.name"
    );

    /** Kept from the stream, since the records themselves are not retained. */
    private String deviceTimezone;

    @Override
    public List<String> paths() {
        return List.of("getprop.txt");
    }

    @Override
    public void parse(AbstractInput artifactInput) throws IOException {
        forEachLine(artifactInput.inputStream, line -> {
            line = line.trim();
            if (line.isEmpty()) return;
            Matcher m = PATTERN.matcher(line);
            if (!m.find() || m.groupCount() < 2) return;
            Map<String, String> entry = new HashMap<>();
            entry.put("name", m.group(1));
            entry.put("value", m.group(2));
            emit(entry);
        });
    }

    @Override
    protected void checkRecord(Object record) {
        @SuppressWarnings("unchecked")
        Map<String, String> property = (Map<String, String>) record;
        String name = property.get("name");
        String value = property.get("value");

        // First occurrence wins, as when the whole property list was scanned in order.
        if (deviceTimezone == null && "persist.sys.timezone".equals(name)) {
            deviceTimezone = value;
        }
        if (Objects.equals(name, "ro.build.version.security_patch")
                && daysSinceSecurityPatchLevel(value) > 180) {
            detected.add(new Detection(DetectionType.GETPROP_SECURITY_PATCH, value));
        }
        /*
        // MVT prints interesting properties as LOG level, we don't really need to report them
        if (INTERESTING_PROPERTIES.contains(name)) {
            detected.add(...);
        }
        */
        // TODO: Check for model and manufacturer

        // Every property is matched, including the ones handled above.
        if (indicators == null) return;
        detected.addAll(indicators.matchString(name, IndicatorType.PROPERTY));
    }

    /** Helper to obtain the timezone property value. */
    public String getDeviceTimezone() {
        return deviceTimezone;
    }

    private long daysSinceSecurityPatchLevel(String patchLevel) {
        if (patchLevel != null && patchLevel.matches("\\d{4}-\\d{2}-\\d{2}")) {
            try {
                java.time.LocalDate patchDate = java.time.LocalDate.parse(patchLevel);
                java.time.LocalDate now = java.time.LocalDate.now();
                // If more than 6 months have passed
                return java.time.temporal.ChronoUnit.DAYS.between(patchDate, now);
            } catch (Exception ignore) {
                // ignore parse errors
            }
        }
        return 0;
    }
}
