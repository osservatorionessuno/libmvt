package org.osservatorionessuno.libmvt.android.artifacts;

import org.junit.jupiter.api.Test;
import org.osservatorionessuno.libmvt.ResourcesUtils;
import org.osservatorionessuno.libmvt.common.AlertLevel;
import org.osservatorionessuno.libmvt.common.DetectionType;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetection;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionCount;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.assertDetectionValue;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.streamArtifact;
import static org.osservatorionessuno.libmvt.common.DetectionTestUtils.streamRecords;

public class DumpsysDevicePolicyTest {

    @Test
    public void testRealDump() throws Exception {
        List<Object> parsed = streamRecords(
                DumpsysDevicePolicy::new,
                "dumpsys.txt",
                ResourcesUtils.readResource("android_data/dumpsys_device_policy.txt"));

        assertEquals(1, parsed.size());
        assertEntry(parsed.get(0), "device_admin", "com.example.infectedwebview",
                "com.example.infectedwebview/.DeviceAdmin", "10");
    }

    @Test
    public void testRealDumpDetections() throws Exception {
        DumpsysDevicePolicy policy = streamArtifact(
                DumpsysDevicePolicy::new,
                "dumpsys.txt",
                ResourcesUtils.readResource("android_data/dumpsys_device_policy.txt"));

        assertDetectionCount(policy.detected, DetectionType.DEVICE_ADMIN, 1);
        assertDetectionCount(policy.detected, DetectionType.DEVICE_OWNER, 0);
        assertDetectionCount(policy.detected, DetectionType.PROFILE_OWNER, 0);
        assertDetectionCount(policy.detected, DetectionType.DEVICE_POLICY_ACCESSIBILITY, 0);
        assertDetection(policy.detected, DetectionType.DEVICE_ADMIN, AlertLevel.INFO);
        assertDetectionValue(policy.detected, DetectionType.DEVICE_ADMIN, List.of(
                "com.example.infectedwebview",
                "com.example.infectedwebview/.DeviceAdmin",
                "user 10"));
    }

    @Test
    public void testAccessibilityServices() throws Exception {
        String dump = """
                DUMP OF SERVICE device_policy:
                Current Device Policy Manager state:
                  Enabled Device Admins (User 0, provisioningState: 0):
                    com.example.infectedwebview/.DeviceAdmin:
                      uid=10130
                    PersonalAppsSuspensionHelper
                      launcher packages: 2 apps
                        0: com.android.launcher3
                        1: com.android.settings
                      accessibility services: 2 apps
                        0: com.example.a11y
                        1: com.google.android.marvin.talkback
                      input method packages: 1 app
                        0: com.android.inputmethod.latin
                """;
        List<Object> parsed = streamRecords(
                DumpsysDevicePolicy::new,
                "dumpsys.txt",
                new ByteArrayInputStream(dump.getBytes(StandardCharsets.UTF_8)));

        assertEquals(3, parsed.size());
        assertEntry(parsed.get(0), "device_admin", "com.example.infectedwebview",
                "com.example.infectedwebview/.DeviceAdmin", "0");
        assertEntry(parsed.get(1), "accessibility", "com.example.a11y", "", "0");
        assertEntry(parsed.get(2), "accessibility", "com.google.android.marvin.talkback", "", "0");
    }

    @Test
    public void testOwners() throws Exception {
        String dump = """
                DUMP OF SERVICE device_policy:
                Current Device Policy Manager state:
                  Device Owner Type: -1
                  Device Owner Component: null
                  Device Owner:
                    admin=ComponentInfo{com.example.mdm/com.example.mdm.AdminReceiver}
                    packageName=com.example.mdm
                  Profile Owner (User 10): ComponentInfo{com.example.work/.ProfileAdmin}
                """;
        List<Object> parsed = streamRecords(
                DumpsysDevicePolicy::new,
                "dumpsys.txt",
                new ByteArrayInputStream(dump.getBytes(StandardCharsets.UTF_8)));

        assertEquals(2, parsed.size());
        assertEntry(parsed.get(0), "device_owner", "com.example.mdm",
                "com.example.mdm/com.example.mdm.AdminReceiver", "");
        assertEntry(parsed.get(1), "profile_owner", "com.example.work",
                "com.example.work/.ProfileAdmin", "10");
    }

    @SuppressWarnings("unchecked")
    private static void assertEntry(
            Object record, String role, String pkg, String component, String user) {
        Map<String, String> item = (Map<String, String>) record;
        assertEquals(role, item.get("role"));
        assertEquals(pkg, item.get("package_name"));
        assertEquals(component, item.get("component"));
        assertEquals(user, item.get("user"));
    }
}
