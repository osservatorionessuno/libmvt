package org.osservatorionessuno.libmvt.android.artifacts

import org.osservatorionessuno.libmvt.common.AbstractInput
import org.osservatorionessuno.libmvt.common.Detection
import org.osservatorionessuno.libmvt.common.DetectionType
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import java.time.format.DateTimeParseException
import java.time.format.ResolverStyle

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
        val section = StringBuilder()
        // Buffer the section: history needs the trailing "ending at:" line, which
        // extractDumpsysSection still delivers before the 79-dash delimiter.
        extractDumpsysSection(artifactInput.inputStream, " settings:") { section.appendLine(it) }
        parseSection(section.toString())
    }

    /** Visible for tests that feed a settings section without the DUMP OF SERVICE frame. */
    fun parseSection(content: String) {
        val sectionEnd = parseSectionEnd(content)
        var namespace: String? = null
        var user: String? = null
        val recordLines = mutableListOf<String>()
        val historyLines = mutableListOf<String>()
        var inHistory = false

        fun flush() {
            if (recordLines.isNotEmpty()) {
                emit(buildRecord(namespace, user, recordLines, historyLines, sectionEnd))
            }
            recordLines.clear()
            historyLines.clear()
            inHistory = false
        }

        for (line in content.lineSequence()) {
            val heading = NAMESPACE_PATTERN.matchEntire(line.trim())
            if (heading != null) {
                flush()
                namespace = heading.groupValues[1].lowercase()
                user = heading.groupValues[2]
                continue
            }

            if (line.startsWith("--------- ")) {
                flush()
                namespace = null
                continue
            }

            if (namespace == null) continue

            // Blank line closes the record: dumpsys prints one after every
            // namespace block / history, and the generation registry follows.
            if (line.isBlank()) {
                flush()
                continue
            }

            if (line.startsWith("_id:")) {
                flush()
                recordLines.add(line)
                continue
            }

            if (recordLines.isEmpty()) continue

            val stripped = line.trim()
            if (stripped.startsWith("History (")) {
                inHistory = true
                continue
            }

            if (inHistory) {
                if (stripped.startsWith("time:")) {
                    historyLines.add(stripped)
                } else if (stripped.isNotEmpty() && historyLines.isNotEmpty()) {
                    historyLines[historyLines.lastIndex] += " $stripped"
                }
                continue
            }

            recordLines.add(line)
        }
        flush()
    }

    override fun checkRecord(record: Any) {
        @Suppress("UNCHECKED_CAST")
        val setting = record as? Map<String, Any?> ?: return
        val key = setting["name"] as? String ?: return
        val value = setting["value"] as? String ?: ""
        val pkg = setting["pkg"] as? String ?: ""

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
                    value,
                ),
            )
        }
    }

    private fun buildRecord(
        namespace: String?,
        user: String?,
        recordLines: List<String>,
        historyLines: List<String>,
        sectionEnd: LocalDateTime?,
    ): Map<String, Any?> {
        var text = recordLines.joinToString("\n").trimEnd()
        // Bare token has no key: shape and is printed last.
        val head = text.removeSuffix(" notPreservedInRestore")
        val record = LinkedHashMap<String, Any?>()
        record["namespace"] = namespace
        record["user"] = user
        record.putAll(splitFields(head, SETTING_FIELDS))
        if (head != text) {
            record["isValuePreservedInRestore"] = "false"
        }
        record["history"] = historyLines.map { parseHistory(it, sectionEnd) }
        return record
    }

    private fun parseHistory(line: String, sectionEnd: LocalDateTime?): Map<String, Any?> {
        val fields = splitFields(line, HISTORY_FIELDS)
        return mapOf(
            "timestamp" to resolveTimestamp(fields["time"].orEmpty(), sectionEnd),
            "oldValue" to fields["oldValue"],
            "newValue" to fields["newValue"],
            "pkg" to fields["package"],
        )
    }

    companion object {
        val DANGEROUS_PACKAGES = setOf("com.android.shell")

        private val SETTING_FIELDS = listOf(
            "_id", "name", "pkg", "value", "default", "defaultSystemSet",
            "tag", "isValuePreservedInRestore",
        )
        private val HISTORY_FIELDS = listOf("time", "mode", "oldValue", "newValue", "package")

        private val NAMESPACE_PATTERN =
            Regex("""^(CONFIG|GLOBAL|SECURE|SYSTEM) SETTINGS \(user (\d+)\)$""")
        private val SECTION_END_PATTERN =
            Regex("""ending at: (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})""")

        private val SECTION_END_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
        // STRICT: SMART would turn 2025-02-29 into 2025-02-28 and break leap-day year search.
        private val HISTORY_PARSE = DateTimeFormatter.ofPattern("uuuu-MM-dd HH:mm:ss.SSS")
            .withResolverStyle(ResolverStyle.STRICT)
        private val HISTORY_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSSSSS")

        /**
         * Split the `key:value` fields of one record. Values are free-form, so a
         * field runs up to the next key that is actually present.
         */
        @JvmStatic
        fun splitFields(text: String, keys: List<String>): Map<String, String> {
            if (keys.isEmpty() || !text.startsWith("${keys[0]}:")) return emptyMap()
            val fields = LinkedHashMap<String, String>()
            var key = keys[0]
            var remainder = text.substring(key.length + 1)
            for (nextKey in keys.drop(1)) {
                val marker = " $nextKey:"
                val at = remainder.indexOf(marker)
                if (at >= 0) {
                    fields[key] = remainder.substring(0, at)
                    key = nextKey
                    remainder = remainder.substring(at + marker.length)
                }
            }
            fields[key] = remainder
            return fields
        }

        @JvmStatic
        fun parseSectionEnd(content: String): LocalDateTime? {
            val match = SECTION_END_PATTERN.find(content) ?: return null
            return try {
                LocalDateTime.parse(match.groupValues[1], SECTION_END_FORMAT)
            } catch (_: DateTimeParseException) {
                null
            }
        }

        /**
         * dumpsys history timestamps lack a year; resolve against [sectionEnd]
         * as the most recent matching date at or before that time.
         */
        @JvmStatic
        fun resolveTimestamp(value: String, sectionEnd: LocalDateTime?): String? {
            if (sectionEnd == null || value.isBlank()) return null
            for (year in sectionEnd.year downTo sectionEnd.year - 8) {
                val timestamp = try {
                    LocalDateTime.parse("$year-$value", HISTORY_PARSE)
                } catch (_: DateTimeParseException) {
                    continue
                }
                if (!timestamp.isAfter(sectionEnd)) {
                    return timestamp.format(HISTORY_FORMAT)
                }
            }
            return null
        }
    }
}
