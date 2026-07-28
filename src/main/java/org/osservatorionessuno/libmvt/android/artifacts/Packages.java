package org.osservatorionessuno.libmvt.android.artifacts;

import com.google.protobuf.CodedInputStream;
import org.osservatorionessuno.libmvt.common.AbstractInput;
import org.osservatorionessuno.libmvt.common.Detection;
import org.osservatorionessuno.libmvt.common.DetectionType;
import org.osservatorionessuno.libmvt.common.Indicators.IndicatorType;
import org.osservatorionessuno.libmvt.common.Utils;
import org.osservatorionessuno.libmvt.android.ProtobufRecords;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Parser for packages.json artifact collected by the `packages` module.
 * This is different from the DumpsysPackages module that use a BugReport artifact instead.
 */
public class Packages extends AndroidArtifact {

    @Override
    public List<String> paths() {
        return List.of("packages.pb", "packages.json");
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
    public void parse(AbstractInput artifactInput) throws IOException {
        results.clear();
        try {
            parseByExtension(artifactInput, this::parseProtobuf, this::parseJson);
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    private void parseProtobuf(InputStream input) throws IOException {
        ProtobufRecords.forEachDelimited(input, record -> {
            CodedInputStream codedInput = CodedInputStream.newInstance(record);
            PackageResult result = parsePackageRecord(codedInput);
            if (result != null) emit(result);
        });
    }

    private PackageResult parsePackageRecord(CodedInputStream input) throws IOException {
        PackageResult result = new PackageResult();
        int tag;
        while ((tag = input.readTag()) != 0) {
            switch (tag >>> 3) {
                case 1 -> result.name = ProtobufRecords.readString(input);
                case 2 -> result.installer = ProtobufRecords.readString(input);
                case 3 -> result.uid = input.readInt32();
                case 4 -> result.disabled = input.readBool();
                case 5 -> result.system = input.readBool();
                case 6 -> result.thirdParty = input.readBool();
                case 7 -> result.files.add(parsePackageFileRecord(
                    CodedInputStream.newInstance(ProtobufRecords.readLengthDelimitedField(input))
                ));
                default -> input.skipField(tag);
            }
        }
        return result;
    }

    private Map<String, Object> parsePackageFileRecord(CodedInputStream input) throws IOException {
        Map<String, Object> fileMap = new HashMap<>();
        // An APK can be signed by several certificates, and SignatureParser collects all of
        // them, so each record appends instead of replacing.
        List<Map<String, Object>> certificates = new ArrayList<>();
        fileMap.put("certificates", certificates);
        int tag;
        while ((tag = input.readTag()) != 0) {
            switch (tag >>> 3) {
                case 1 -> fileMap.put("path", ProtobufRecords.readString(input));
                case 2 -> fileMap.put("local_name", ProtobufRecords.readString(input));
                case 3 -> fileMap.put("md5", ProtobufRecords.readString(input));
                case 4 -> fileMap.put("sha1", ProtobufRecords.readString(input));
                case 5 -> fileMap.put("sha256", ProtobufRecords.readString(input));
                case 6 -> fileMap.put("sha512", ProtobufRecords.readString(input));
                case 7 -> fileMap.put("suspicious", input.readBool());
                case 8 -> certificates.add(parsePackageCertificateRecord(
                    CodedInputStream.newInstance(ProtobufRecords.readLengthDelimitedField(input))
                ));
                //case 9 -> fileMap.put("infiles", ProtobufRecords.readString(input));
                default -> input.skipField(tag);
            }
        }
        fileMap.putIfAbsent("path", "");
        fileMap.putIfAbsent("local_name", "");
        fileMap.putIfAbsent("md5", "");
        fileMap.putIfAbsent("sha1", "");
        fileMap.putIfAbsent("sha256", "");
        fileMap.putIfAbsent("sha512", "");
        return fileMap;
    }

    private Map<String, Object> parsePackageCertificateRecord(CodedInputStream input) throws IOException {
        Map<String, Object> certificateMap = new HashMap<>();
        int tag;
        while ((tag = input.readTag()) != 0) {
            switch (tag >>> 3) {
                case 1 -> certificateMap.put("md5", ProtobufRecords.readString(input));
                case 2 -> certificateMap.put("sha1", ProtobufRecords.readString(input));
                case 3 -> certificateMap.put("sha256", ProtobufRecords.readString(input));
                case 4 -> certificateMap.put("valid_from", ProtobufRecords.readString(input));
                case 5 -> certificateMap.put("valid_to", ProtobufRecords.readString(input));
                case 6 -> certificateMap.put("issuer", ProtobufRecords.readString(input));
                case 7 -> certificateMap.put("subject", ProtobufRecords.readString(input));
                case 8 -> certificateMap.put("signature_algorithm", ProtobufRecords.readString(input));
                case 9 -> certificateMap.put("serial_number", ProtobufRecords.readString(input));
                default -> input.skipField(tag);
            }
        }
        return certificateMap;
    }

    private void parseJson(InputStream input) throws IOException {
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
                emit(result);
            }
        } catch (JSONException ex) {
            // TODO: Something went wrong
        }
    }

    /** Records are checked by {@link #checkRecord} as they stream in; none are retained. */
    @Override
    public void checkIndicators() {
    }

    @Override
    protected void checkRecord(Object record) {
        PackageResult result = (PackageResult) record;

        if (Utils.ROOT_PACKAGES.contains(result.name)) {
            detected.add(new Detection(DetectionType.PACKAGES_ROOT_PACKAGE, result.name));
            return;
        }

        if ("null".equals(result.installer) && !result.system) {
            detected.add(new Detection(DetectionType.PACKAGES_ADB_INSTALLED, result.name));
        } else if (Utils.THIRD_PARTY_STORE_INSTALLERS.contains(result.installer)) {
            detected.add(new Detection(DetectionType.PACKAGES_THIRD_PARTY_STORE_INSTALLED,
                result.name, result.installer));
        } else if (Utils.BROWSER_INSTALLERS.contains(result.installer)) {
            detected.add(new Detection(DetectionType.PACKAGES_BROWSER_INSTALLED,
                result.name, result.installer));
        }

        if (Utils.SECURITY_PACKAGES.contains(result.name) && result.disabled) {
            detected.add(new Detection(DetectionType.PACKAGES_SECURITY_DISABLED, result.name));
        }

        if (Utils.SYSTEM_UPDATE_PACKAGES.contains(result.name) && result.disabled) {
            detected.add(new Detection(DetectionType.PACKAGES_SYSTEM_UPDATE_DISABLED, result.name));
        }

        if (indicators == null) return;

        detected.addAll(indicators.matchString(result.name, IndicatorType.APP_ID));
        for (Map<String, Object> packageFile : result.files) {
            addPackageIocMatches(result.name, (String) packageFile.get("path"), IndicatorType.FILE_PATH);
            addPackageIocMatches(result.name, (String) packageFile.get("md5"), IndicatorType.FILE_HASH_MD5);
            addPackageIocMatches(result.name, (String) packageFile.get("sha1"), IndicatorType.FILE_HASH_SHA1);
            addPackageIocMatches(result.name, (String) packageFile.get("sha256"), IndicatorType.FILE_HASH_SHA256);

            Object certificatesObj = packageFile.get("certificates");
            if (!(certificatesObj instanceof List<?> certList)) continue;

            for (Object certObj : certList) {
                if (!(certObj instanceof Map<?, ?> certAny)) continue;

                Object md5Obj = certAny.get("md5");
                Object sha1Obj = certAny.get("sha1");
                Object sha256Obj = certAny.get("sha256");

                addPackageIocMatches(result.name,
                        md5Obj instanceof String ? (String) md5Obj : null,
                        IndicatorType.APP_CERT_HASH_MD5);
                addPackageIocMatches(result.name,
                        sha1Obj instanceof String ? (String) sha1Obj : null,
                        IndicatorType.APP_CERT_HASH_SHA1);
                addPackageIocMatches(result.name,
                        sha256Obj instanceof String ? (String) sha256Obj : null,
                        IndicatorType.APP_CERT_HASH_SHA256);
            }
        }
    }

    private void addPackageIocMatches(String packageName, String matched, IndicatorType type) {
        if (indicators == null || matched == null || matched.trim().isEmpty()) return;
        for (Detection detection : indicators.matchString(matched, type)) {
            List<String> value = new ArrayList<>(detection.getValue());
            value.add(packageName);
            detected.add(new Detection(DetectionType.IOC_MATCH, value));
        }
    }
}
