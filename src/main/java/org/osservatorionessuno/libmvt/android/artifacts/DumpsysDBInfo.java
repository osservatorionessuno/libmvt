package org.osservatorionessuno.libmvt.android.artifacts;

import org.osservatorionessuno.libmvt.common.AbstractInput;
import org.osservatorionessuno.libmvt.common.Indicators.IndicatorType;

import java.util.*;
import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Parser for dumpsys dbinfo output. */
public class DumpsysDBInfo extends DumpsysArtifact {
    private static final Pattern RXP = Pattern.compile(".*\\[([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3})\\].*\\[Pid:\\((\\d+)\\)\\](\\w+).*sql=\\\"(.+?)\\\"");
    private static final Pattern RXP_NO_PID = Pattern.compile(".*\\[([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3})\\][ ]{1}(\\w+).*sql=\\\"(.+?)\\\"");

    @Override
    public void parse(AbstractInput artifactInput) throws IOException {
        results.clear();
        String[] pool = { null };
        boolean[] inOperations = { false };

        extractDumpsysSection(artifactInput.inputStream, "dbinfo:", line -> {
            if (line.startsWith("Connection pool for ")) {
                pool[0] = line.replace("Connection pool for ", "").replaceFirst(":$", "");
            }
            if (pool[0] == null) return;
            if (line.trim().equals("Most recently executed operations:")) {
                inOperations[0] = true;
                return;
            }
            if (!inOperations[0]) return;
            if (!line.startsWith("        ")) {
                inOperations[0] = false;
                pool[0] = null;
                return;
            }
            Matcher m = RXP.matcher(line);
            if (m.find()) {
                Map<String, String> map = new HashMap<>();
                map.put("isodate", m.group(1));
                map.put("pid", m.group(2));
                map.put("action", m.group(3));
                map.put("sql", m.group(4));
                map.put("path", pool[0]);
                results.add(map);
            } else {
                Matcher m2 = RXP_NO_PID.matcher(line);
                if (!m2.find()) return;
                Map<String, String> map = new HashMap<>();
                map.put("isodate", m2.group(1));
                map.put("action", m2.group(2));
                map.put("sql", m2.group(3));
                map.put("path", pool[0]);
                results.add(map);
            }
        });
    }

    @Override
    public void checkIndicators() {
        if (indicators == null) return;
        for (Object obj : results) {
            @SuppressWarnings("unchecked")
            Map<String, String> map = (Map<String, String>) obj;
            String path = map.getOrDefault("path", "");
            for (String part : path.split("/")) {
                detected.addAll(indicators.matchString(part, IndicatorType.APP_ID));
            }
        }
    }
}
