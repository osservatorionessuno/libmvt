package org.osservatorionessuno.libmvt.android.artifacts

import org.osservatorionessuno.libmvt.common.AbstractInput
import org.osservatorionessuno.libmvt.common.Detection
import org.osservatorionessuno.libmvt.common.DetectionType

/**
 * Parser for the device_policy service inside a bugreport dumpsys.
 *
 * Picks out device admins (`pkg/.Class:` under Enabled Device Admins), device and profile
 * owners, and enabled accessibility services (`accessibility services:` in
 * PersonalAppsSuspensionHelper). Unrecognised lines are ignored.
 */
class DumpsysDevicePolicy : DumpsysArtifact() {

    override fun parse(artifactInput: AbstractInput) {
        var user = ""
        var ownerRole: String? = null
        var accessibilityLeft = 0

        extractDumpsysSection(artifactInput.inputStream, " device_policy:") { raw ->
            val line = raw.trim()
            if (line.isEmpty()) return@extractDumpsysSection

            USER_IN_PARENS.find(line)?.let { user = it.groupValues[1] }

            val accessibility = ACCESSIBILITY_HEADER.matchEntire(line)
            if (accessibility != null) {
                accessibilityLeft = accessibilityCount(accessibility.groupValues[1])
                return@extractDumpsysSection
            }
            if (accessibilityLeft > 0) {
                val pkg = INDEXED_PACKAGE.matchEntire(line)?.groupValues?.get(1)
                if (pkg != null) {
                    emit(record("accessibility", pkg, "", user))
                    accessibilityLeft--
                    return@extractDumpsysSection
                }
                accessibilityLeft = 0
            }

            val role = ownerRole(line)
            if (role != null) {
                ownerRole = if (line.endsWith("null")) null else role
                val pkg = packageOf(line)
                if (pkg != null) {
                    emit(record(role, pkg, componentOf(line), user))
                    ownerRole = null
                }
                return@extractDumpsysSection
            }
            if (ownerRole != null) {
                val pkg = packageOf(line)
                if (pkg != null) {
                    emit(record(ownerRole!!, pkg, componentOf(line), user))
                    ownerRole = null
                    return@extractDumpsysSection
                }
                if (line == "null" || !line.contains('=')) ownerRole = null else return@extractDumpsysSection
            }

            val admin = adminOf(line) ?: return@extractDumpsysSection
            emit(record("device_admin", admin.first, admin.second, user))
        }
    }

    override fun checkRecord(record: Any) {
        @Suppress("UNCHECKED_CAST")
        val item = record as? Map<String, String> ?: return
        val type = when (item["role"]) {
            "device_owner" -> DetectionType.DEVICE_OWNER
            "profile_owner" -> DetectionType.PROFILE_OWNER
            "device_admin" -> DetectionType.DEVICE_ADMIN
            "accessibility" -> DetectionType.DEVICE_POLICY_ACCESSIBILITY
            else -> return
        }
        val packageName = item["package_name"] ?: return
        if (packageName.isEmpty()) return
        val values = ArrayList<String>()
        values.add(packageName)
        val component = item["component"] ?: ""
        if (component.isNotEmpty()) values.add(component)
        val userId = item["user"] ?: ""
        if (userId.isNotEmpty()) values.add("user $userId")
        detected.add(Detection(type, values))
    }

    private fun record(role: String, pkg: String, component: String, user: String) = mapOf(
        "role" to role,
        "package_name" to pkg,
        "component" to component,
        "user" to user,
    )

    /** `empty` -> 0, `2 apps` / `1 app` -> that count, anything else -> 0. */
    private fun accessibilityCount(value: String): Int {
        if (value == "empty") return 0
        return APP_COUNT.matchEntire(value)?.groupValues?.get(1)?.toIntOrNull() ?: 0
    }

    private fun ownerRole(line: String): String? = when {
        line.startsWith("Device Owner Type") || line.startsWith("Device Owner User") -> null
        line.startsWith("Device Owner") -> "device_owner"
        line.startsWith("Profile Owner") -> "profile_owner"
        else -> null
    }

    private fun packageOf(line: String): String? {
        val named = (PACKAGE_NAME.find(line) ?: PACKAGE.find(line))?.groupValues?.get(1)
        if (named != null && named != "null") return named
        return COMPONENT_INFO.find(line)?.groupValues?.get(1)
    }

    private fun componentOf(line: String): String {
        val info = COMPONENT_INFO.find(line) ?: return ""
        return "${info.groupValues[1]}/${info.groupValues[2]}"
    }

    /** An enabled-admin entry, `pkg/.Class:` or `ComponentInfo{pkg/class}:`. */
    private fun adminOf(line: String): Pair<String, String>? {
        if (!line.endsWith(":")) return null
        val body = line.removeSuffix(":")
        if (body.contains('=') || body.contains(' ')) return null
        val info = COMPONENT_INFO.find(body)
        if (info != null && body.startsWith("ComponentInfo{")) {
            val pkg = info.groupValues[1]
            return pkg to "$pkg/${info.groupValues[2]}"
        }
        val slash = body.indexOf('/')
        if (slash <= 0 || !body.substring(0, slash).contains('.')) return null
        return body.substring(0, slash) to body
    }

    private companion object {
        val USER_IN_PARENS = Regex("""\(User (\d+)""")
        val ACCESSIBILITY_HEADER = Regex("""^accessibility services: (.+)$""")
        val APP_COUNT = Regex("""^(\d+) apps?$""")
        val INDEXED_PACKAGE = Regex("""^\d+:\s+(\S+)$""")
        val COMPONENT_INFO = Regex("""ComponentInfo\{([^/}]+)/([^}]+)}""")
        val PACKAGE_NAME = Regex("""(?:^|[\s{,])packageName=([^\s,}]+)""")
        val PACKAGE = Regex("""(?:^|[\s{,])package=([^\s,}]+)""")
    }
}
