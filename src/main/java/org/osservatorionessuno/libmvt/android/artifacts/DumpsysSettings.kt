package org.osservatorionessuno.libmvt.android.artifacts

import org.osservatorionessuno.libmvt.common.AbstractInput
import org.osservatorionessuno.libmvt.common.Detection
import org.osservatorionessuno.libmvt.common.DetectionType

/**
 * Parser for the settings service inside a bugreport dumpsys.
 *
 * AndroidQF key=value files are handled by [Settings]. This reads the
 * `dumpsys settings` blocks (`GLOBAL SETTINGS`, `SECURE SETTINGS`, …), whose
 * values can span lines, and applies the same dangerous-setting checks plus
 * settings last written by a dangerous package.
 */
class DumpsysSettings : DumpsysArtifact() {

    override fun parse(artifactInput: AbstractInput) {
        var namespace: String? = null
        val current = StringBuilder()

        fun flush() {
            if (namespace == null || current.isEmpty()) {
                current.clear()
                return
            }
            val fields = parseSetting(current.toString())
            current.clear()
            val name = fields["name"] ?: return
            emit(
                mapOf(
                    "namespace" to namespace,
                    "name" to name,
                    "value" to (fields["value"] ?: ""),
                    "pkg" to (fields["pkg"] ?: ""),
                )
            )
        }

        // " settings:" so notification_settings and similar services do not match.
        extractDumpsysSection(artifactInput.inputStream, " settings:") { raw ->
            val line = raw.trim()
            if (line.isEmpty()) {
                if (current.isNotEmpty()) current.append('\n')
                return@extractDumpsysSection
            }
            val nextNamespace = namespaceOf(line)
            if (nextNamespace != null) {
                flush()
                namespace = nextNamespace
                return@extractDumpsysSection
            }
            if (namespace == null) return@extractDumpsysSection
            if (line.lowercase().startsWith("version")) return@extractDumpsysSection
            if (line.startsWith("_id:")) {
                flush()
                current.append(line)
            } else if (current.isNotEmpty()) {
                current.append('\n').append(raw)
            }
        }
        flush()
    }

    override fun checkRecord(record: Any) {
        @Suppress("UNCHECKED_CAST")
        val setting = record as? Map<String, String> ?: return
        val key = setting["name"] ?: return
        val value = setting["value"] ?: ""
        val pkg = setting["pkg"] ?: ""

        val description = Settings.getUnsafeSettingDescription(key, value)
        if (description != null) {
            detected.add(Detection(DetectionType.DANGEROUS_SETTINGS, description, key, value))
        }
        if (pkg in DANGEROUS_PACKAGES) {
            detected.add(
                Detection(
                    DetectionType.DANGEROUS_SETTINGS,
                    "was modified by $pkg",
                    key,
                    value
                )
            )
        }
    }

    private fun namespaceOf(line: String): String? = when {
        line.startsWith("CONFIG SETTINGS") -> "config"
        line.startsWith("GLOBAL SETTINGS") -> "global"
        line.startsWith("SECURE SETTINGS") -> "secure"
        line.startsWith("SYSTEM SETTINGS") -> "system"
        else -> null
    }

    /**
     * Fields are marked in order (` name:`, ` pkg:`, ` value:`, …). A value may
     * contain spaces and newlines, so this slices on those markers rather than
     * splitting on whitespace.
     */
    private fun parseSetting(setting: String): Map<String, String> {
        val fields = LinkedHashMap<String, String>()
        var offset = 0
        for (marker in FIELD_MARKERS) {
            val end = if (marker == END) setting.length else setting.indexOf(marker)
            if (end <= 0) continue
            val substr = setting.substring(offset, end).trim()
            val colon = substr.indexOf(':')
            if (colon > 0) {
                fields[substr.substring(0, colon).trim()] = substr.substring(colon + 1).trim()
            }
            offset = end
        }
        return fields
    }

    private companion object {
        val DANGEROUS_PACKAGES = setOf("com.android.shell")
        const val END = "end"
        val FIELD_MARKERS = listOf(" name:", " pkg:", " value:", " default:", " defaultSystemSet:", END)
    }
}
