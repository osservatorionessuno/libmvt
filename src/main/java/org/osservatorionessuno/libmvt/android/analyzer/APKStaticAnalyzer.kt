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
            LogUtils.d("APKStaticAnalyzer", "Manifest couldn't be parsed")
            return true
        }
        val application = el.getElementsByTagName("application").item(0) as? Element ?: return true

        // Check for Accessibility services.
        val services = application.getElementsByTagName("service")
        for (i in 0 until services.length) {
            val service = services.item(i) as? Element ?: continue

            val permission = service.getAttributeNS(ManifestParser.ANDROID_NS, "permission")
            if (permission.isEmpty()) { continue }
            if (permission.contains("android.permission.BIND_ACCESSIBILITY_SERVICE")) {
                // App has an Accessibility service.
                LogUtils.d("APKStaticAnalyzer", "Accessibility service found: $permission")
                return true
            }
        }

        // Check if isAccessbilityTool is true.
        val isAccessbilityTool = application.getAttributeNS(ManifestParser.ANDROID_NS, "isAccessbilityTool")
        if (isAccessbilityTool == "true") {
            // App is an Accessibility tool.
            LogUtils.d("APKStaticAnalyzer", "Accessibility tool found")
            return true
        }
        
        // Check for dangerous permissions.
        var counter = 0
        val usesPermissions = el.getElementsByTagName("uses-permission")
        for (i in 0 until usesPermissions.length) {
            val usesPermission = usesPermissions.item(i) as? Element ?: continue
            val name =
                usesPermission.getAttributeNS(ManifestParser.ANDROID_NS, "name").ifEmpty {
                    usesPermission.getAttribute("android:name")
                }
            if (name.isEmpty()) { continue }

            // If an APK has one of these permissions, we want to analyze it further.
            if (Utils.EXTRA_DANGEROUS_PERMISSIONS.contains(name)) {
                LogUtils.d("APKStaticAnalyzer", "Extra dangerous permission found: $name")
                return true
            }
            if (Utils.DANGEROUS_PERMISSIONS.contains(name)) {
                LogUtils.d("APKStaticAnalyzer", "Dangerous permission found: $name")
                counter++
            }
        }

        // Too many dangerous permissions found, return true.
        if (counter > Utils.DANGEROUS_PERMISSIONS_THRESHOLD) {
            LogUtils.d("APKStaticAnalyzer", "Too many dangerous permissions found: $counter")
            return true
        }

        // Maybe the APK is not suspicious...
        return false
    }
}
