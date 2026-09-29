package org.osservatorionessuno.libmvt.android.analyzer

import org.osservatorionessuno.libmvt.common.logging.LogUtils
import org.osservatorionessuno.libmvt.android.parsers.ManifestParser
import org.osservatorionessuno.libmvt.common.Utils
import org.w3c.dom.Document
import org.w3c.dom.Element

/* 
 * This class is a very very very basic static analyzer for APKs.
 * 
 * Its goal is determine if an APK is worth dumping for further analysis,
 * since Bugbane exports must not weight too much disk space.
 * 
 * It just checks for dangerous permissions or Accessibility services.
 */
object APKStaticAnalyzer {
    @JvmStatic
    fun analyze(manifest: Document): Boolean {
        val el = manifest.documentElement
        if (el == null) {
            // Manifest couldn't be parsed, return true.
            LogUtils.w("APKStaticAnalyzer", "Manifest couldn't be parsed")
            return true
        }
        val application = el.getElementsByTagName("application").item(0) as? Element ?: return true

        // We don't do early return so we can log all the risky things found.
        var highRisk = false

        // Check for Accessibility services.
        val services = application.getElementsByTagName("service")
        for (i in 0 until services.length) {
            val service = services.item(i) as? Element ?: continue

            val permission = service.getAttributeNS(ManifestParser.ANDROID_NS, "permission")
            if (permission.isEmpty()) { continue }
            if (permission.contains("android.permission.BIND_ACCESSIBILITY_SERVICE")) {
                // App has an Accessibility service.
                LogUtils.i("APKStaticAnalyzer", "Accessibility service found: $permission")
                highRisk = true
            }
        }

        // Check if isAccessbilityTool is true.
        val isAccessbilityTool = application.getAttributeNS(ManifestParser.ANDROID_NS, "isAccessbilityTool")
        if (isAccessbilityTool == "true") {
            // App is an Accessibility tool.
            LogUtils.i("APKStaticAnalyzer", "Accessibility tool found")
            highRisk = true
        }

        // Check for Device Admin receivers.
        val receivers = application.getElementsByTagName("receiver")
        for (i in 0 until receivers.length) {
            val receiver = receivers.item(i) as? Element ?: continue

            val permission = receiver.getAttributeNS(ManifestParser.ANDROID_NS, "permission")
            if (permission.isEmpty()) { continue }
            if (permission.contains("android.permission.BIND_DEVICE_ADMIN")) {
                // App is a Device Admin.
                LogUtils.i("APKStaticAnalyzer", "Device Admin receiver found: $permission")
                highRisk = true
            }
        }
        
        // Check for dangerous permissions.
        val permissionNames = ArrayList<String>()
        val usesPermissions = el.getElementsByTagName("uses-permission")
        for (i in 0 until usesPermissions.length) {
            val usesPermission = usesPermissions.item(i) as? Element ?: continue
            val name =
                usesPermission.getAttributeNS(ManifestParser.ANDROID_NS, "name").ifEmpty {
                    usesPermission.getAttribute("android:name")
                }
            if (name.isEmpty()) continue
            permissionNames.add(name)
        }
        if (permissionsLookSuspicious(permissionNames)) {
            LogUtils.i("APKStaticAnalyzer", "Dangerous permissions heuristic matched. APK likely risky.")
            highRisk = true
        }

        // Return true if the APK is risky, false if we cannot determine if it is malicious.
        return highRisk
    }

    /**
     * Permission-only half of [APKStaticAnalyzer]:
     * true if any [Utils.EXTRA_DANGEROUS_PERMISSIONS] hit or more than [Utils.DANGEROUS_PERMISSIONS_THRESHOLD]
     * [Utils.DANGEROUS_PERMISSIONS] are requested.
     */
    @JvmStatic
    fun permissionsLookSuspicious(permissions: Iterable<String>): Boolean {
        var counter = 0
        for (name in permissions) {
            if (Utils.EXTRA_DANGEROUS_PERMISSIONS.contains(name)) {
                LogUtils.i("APKStaticAnalyzer", "Extra dangerous permission found: $name")
                return true
            }
            if (Utils.DANGEROUS_PERMISSIONS.contains(name)) {
                LogUtils.i("APKStaticAnalyzer", "Dangerous permission found: $name")
                counter++
            }
        }
        return counter > Utils.DANGEROUS_PERMISSIONS_THRESHOLD
    }

}
