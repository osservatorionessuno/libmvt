package org.osservatorionessuno.libmvt.android.artifacts;

import org.osservatorionessuno.libmvt.common.AlertLevel;
import org.osservatorionessuno.libmvt.common.Detection;
import org.osservatorionessuno.libmvt.common.Indicators.IndicatorType;
import org.osservatorionessuno.libmvt.common.Utils;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.io.IOException;
import java.io.InputStream;

/**
 * Parser for packages.json artifact collected by the `packages` module.
 * This is different from the DumpsysPackages module that use a BugReport artifact instead.
 */
public class Packages extends AndroidArtifact {

    @Override
    public List<String> paths() {
        return List.of("packages.json");
    }

    private static class PackageResult {
        String name = "";
        Boolean disabled = false;
        String installer = "";
        Integer uid = null;
        Boolean system = false;
        Boolean thirdParty = false;
        List<Map<String, Object>> files = new ArrayList<>();

        @Override
        public String toString() {
            return "PackageResult(name=" + name + ", disabled=" + disabled + ", installer=" + installer + ", uid=" + uid + ", system=" + system + ", thirdParty=" + thirdParty + ", files=" + files + ")";
        }
    }

    @Override
    public void parse(InputStream input) throws IOException {
        try {
            // Try to parse the input as a JSON array
            JSONArray arr = new JSONArray(collectText(input));
            for (int i = 0; i < arr.length(); i++) {
                JSONObject obj = arr.getJSONObject(i);

                PackageResult result = new PackageResult();
                result.name = obj.getString("name");
                result.disabled = obj.getBoolean("disabled");
                result.installer = obj.getString("installer");
                result.uid = obj.getInt("uid");
                result.system = obj.getBoolean("system");
                result.thirdParty = obj.getBoolean("third_party");
                
                JSONArray filesArray = obj.getJSONArray("files");
                for (int j = 0; j < filesArray.length(); j++) {
                    JSONObject fileObj = filesArray.getJSONObject(j);
                    List<Map<String, String>> certs = new ArrayList<>();

                    // AndroidQF format: { "certificate": { "Md5": "...", "Sha1": "...", "Sha256": "..." } }
                    JSONObject certificateInfo = fileObj.optJSONObject("certificate");
                    if (certificateInfo != null) {
                        String md5 = certificateInfo.optString("Md5", null);
                        String sha1 = certificateInfo.optString("Sha1", null);
                        String sha256 = certificateInfo.optString("Sha256", null);

                        Map<String, String> certMap = new HashMap<>();
                        if (md5 != null) certMap.put("md5", md5);
                        if (sha1 != null) certMap.put("sha1", sha1);
                        if (sha256 != null) certMap.put("sha256", sha256);
                        if (!certMap.isEmpty()) certs.add(certMap);
                    }

                    // Bugbane format: { "certificates": [ { "md5": "...", "sha1": "...", "sha256": "..." }, ... ] }
                    JSONArray certificates = fileObj.optJSONArray("certificates");
                    if (certificates != null) {
                        for (int k = 0; k < certificates.length(); k++) {
                            JSONObject cert = certificates.optJSONObject(k);
                            if (cert == null) continue;
                            Map<String, String> certMap = new HashMap<>();
                            String md5 = cert.optString("md5", null);
                            String sha1 = cert.optString("sha1", null);
                            String sha256 = cert.optString("sha256", null);
                            if (md5 != null) certMap.put("md5", md5);
                            if (sha1 != null) certMap.put("sha1", sha1);
                            if (sha256 != null) certMap.put("sha256", sha256);
                            if (!certMap.isEmpty()) certs.add(certMap);
                        }
                    }

                    Map<String, Object> fileMap = new HashMap<>();
                    fileMap.put("path", fileObj.optString("path", ""));
                    fileMap.put("local_name", fileObj.optString("local_name", ""));
                    fileMap.put("md5", fileObj.optString("md5", ""));
                    fileMap.put("sha1", fileObj.optString("sha1", ""));
                    fileMap.put("sha256", fileObj.optString("sha256", ""));
                    fileMap.put("sha512", fileObj.optString("sha512", ""));
                    fileMap.put("certificates", certs);

                    result.files.add(fileMap);
                }
                results.add(result);
            }
        } catch (JSONException ex) {
            // TODO: Something went wrong
        }
    }

    @Override
    public void checkIndicators() {
        for (Object r : results) {
            PackageResult result = (PackageResult) r;

            if (Utils.ROOT_PACKAGES.contains(result.name)) {
                detected.add(new Detection(AlertLevel.MEDIUM, getString("mvt_packages_root_package_title"),
                    String.format(
                        getString("mvt_packages_root_package_message"),
                        result.name
                    )));
                continue;
            }

            if ("null".equals(result.installer) && !result.system) {
                detected.add(new Detection(AlertLevel.HIGH, getString("mvt_packages_non_system_package_title"),
                    String.format(
                        getString("mvt_packages_non_system_package_message"),
                        result.name
                    )));
            } else if (Utils.THIRD_PARTY_STORE_INSTALLERS.contains(result.installer)) {
                detected.add(new Detection(AlertLevel.INFO, getString("mvt_packages_third_party_store_package_title"),
                    String.format(
                        getString("mvt_packages_third_party_store_package_message"),
                        result.installer,
                        result.name
                    )));
            } else if (Utils.BROWSER_INSTALLERS.contains(result.installer)) {
                detected.add(new Detection(AlertLevel.MEDIUM, getString("mvt_packages_browser_package_title"),
                    String.format(
                        getString("mvt_packages_browser_package_message"),
                        result.installer,
                        result.name
                    )));
            }


            if (Utils.SECURITY_PACKAGES.contains(result.name) && result.disabled) {
                detected.add(new Detection(AlertLevel.MEDIUM, getString("mvt_packages_security_package_title"),
                    String.format(
                        getString("mvt_packages_security_package_message"),
                        result.name
                    )));
            }

            if (Utils.SYSTEM_UPDATE_PACKAGES.contains(result.name) && result.disabled) {
                detected.add(new Detection(AlertLevel.MEDIUM, getString("mvt_packages_system_update_package_title"),
                    String.format(
                        getString("mvt_packages_system_update_package_message"),
                        result.name
                    )));
            }

            // Continnue instead of returning because we want to check indicators for all packages.
            if (indicators == null) continue;

            detected.addAll(indicators.matchString(result.name, IndicatorType.APP_ID));
            for (Map<String, Object> packageFile : result.files) {
                detected.addAll(indicators.matchString((String) packageFile.get("path"), IndicatorType.FILE_PATH));
                detected.addAll(indicators.matchString((String) packageFile.get("md5"), IndicatorType.FILE_HASH_MD5));
                detected.addAll(indicators.matchString((String) packageFile.get("sha1"), IndicatorType.FILE_HASH_SHA1));
                detected.addAll(indicators.matchString((String) packageFile.get("sha256"), IndicatorType.FILE_HASH_SHA256));

                Object certificatesObj = packageFile.get("certificates");
                if (!(certificatesObj instanceof List<?> certList)) continue;

                for (Object certObj : certList) {
                    if (!(certObj instanceof Map<?, ?> certAny)) continue;

                    Object md5Obj = certAny.get("md5");
                    Object sha1Obj = certAny.get("sha1");
                    Object sha256Obj = certAny.get("sha256");

                    detected.addAll(indicators.matchString(md5Obj instanceof String ? (String) md5Obj : null, IndicatorType.APP_CERT_HASH_MD5));
                    detected.addAll(indicators.matchString(sha1Obj instanceof String ? (String) sha1Obj : null, IndicatorType.APP_CERT_HASH_SHA1));
                    detected.addAll(indicators.matchString(sha256Obj instanceof String ? (String) sha256Obj : null, IndicatorType.APP_CERT_HASH_SHA256));
                }
            }
        }
    }
}
