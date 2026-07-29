package org.osservatorionessuno.libmvt.android.artifacts;

import org.osservatorionessuno.libmvt.common.AbstractInput;
import org.osservatorionessuno.libmvt.common.Indicators.IndicatorType;

import java.util.*;
import java.io.IOException;

/** Parser for dumpsys platform_compat output. */
public class DumpsysPlatformCompat extends DumpsysArtifact {

    @Override
    public void parse(AbstractInput artifactInput) throws IOException {
        if (artifactInput.inputStream == null) return;

        extractDumpsysSection(artifactInput.inputStream, "platform_compat:", line -> {
            line = line.trim();
            if (!line.startsWith("ChangeId(168419799; name=DOWNSCALED")) return;
            int idx = line.indexOf("rawOverrides={");
            if (idx < 0) return;
            String overrides = line.substring(idx + 14);
            int end = overrides.indexOf("};");
            if (end >= 0) overrides = overrides.substring(0, end);
            for (String entry : overrides.split(",")) {
                String pkg = entry.split("=")[0].trim();
                Map<String, String> rec = new HashMap<>();
                rec.put("package_name", pkg);
                emit(rec);
            }
        });
    }

    @Override
    protected void checkRecord(Object record) {
        if (indicators == null) return;
        @SuppressWarnings("unchecked")
        Map<String, String> override = (Map<String, String>) record;
        detected.addAll(indicators.matchString(override.get("package_name"), IndicatorType.APP_ID));
    }
}
