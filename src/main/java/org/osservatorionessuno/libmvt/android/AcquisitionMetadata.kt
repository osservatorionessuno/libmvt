package org.osservatorionessuno.libmvt.android

import org.json.JSONObject
import java.io.File
import java.time.Instant
import java.time.OffsetDateTime
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.zip.ZipFile

/**
 * Metadata from an AndroidQF / Bugbane [ACQUISITION_FILE] inside an acquisition.
 */
data class AcquisitionMetadata(
    val created: String?,
    val completed: String?,
    val bugbaneVersion: String?,
    val androidqfVersion: String?,
) {
    /** Human-readable [created], or null if unset. */
    val createdFormatted: String? get() = formatTimestamp(created)

    /** Human-readable [completed], or null if unset. */
    val completedFormatted: String? get() = formatTimestamp(completed)

    fun toJsonObject(): JSONObject =
        JSONObject().apply {
            putOpt("created", created)
            putOpt("completed", completed)
            putOpt("bugbane_version", bugbaneVersion)
            putOpt("androidqf_version", androidqfVersion)
        }

    companion object {
        const val ACQUISITION_FILE = "acquisition.json"

        /** Go's zero time (`time.Time{}`); anything at or before this is "unset". */
        private val GO_ZERO_TIME: Instant = Instant.parse("0001-01-01T00:00:00Z")

        private val DISPLAY_FORMAT: DateTimeFormatter =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss 'UTC'").withZone(ZoneOffset.UTC)

        @JvmStatic
        fun load(input: File): AcquisitionMetadata? {
            val text = readAcquisitionJson(input) ?: return null
            return fromJson(text)
        }

        @JvmStatic
        fun fromJson(text: String): AcquisitionMetadata {
            val root = JSONObject(text)
            val created = root.optString("created")
                .ifBlank { root.optString("started") }
                .asMeaningfulTimestamp()
            val completed = root.optString("completed").asMeaningfulTimestamp()
            val bugbaneVersion = root.optString("bugbane_version").nullIfBlank()
            val androidqfVersion = root.optString("androidqf_version").nullIfBlank()
            return AcquisitionMetadata(
                created = created,
                completed = completed,
                bugbaneVersion = bugbaneVersion,
                androidqfVersion = androidqfVersion,
            )
        }

        @JvmStatic
        fun formatTimestamp(raw: String?): String? {
            val text = raw?.nullIfBlank() ?: return null
            val instant = parseInstant(text) ?: return text
            return DISPLAY_FORMAT.format(instant)
        }

        private fun readAcquisitionJson(input: File): String? =
            when {
                input.isDirectory -> {
                    val file = File(input, ACQUISITION_FILE)
                    if (file.isFile) file.readText() else null
                }
                input.isFile && input.name.lowercase().endsWith(".zip") -> {
                    ZipFile(input).use { zip ->
                        val entry = zip.entries().asSequence().firstOrNull { e ->
                            !e.isDirectory &&
                                e.name.replace('\\', '/').substringAfterLast('/') == ACQUISITION_FILE
                        } ?: return null
                        zip.getInputStream(entry).bufferedReader().use { it.readText() }
                    }
                }
                else -> null
            }

        /**
         * Returns [this] when it parses to a real instant after Go's zero time;
         * null for blank or year-1 placeholders.
         */
        private fun String.asMeaningfulTimestamp(): String? {
            val text = nullIfBlank() ?: return null
            val instant = parseInstant(text) ?: return text
            return if (instant.isAfter(GO_ZERO_TIME)) text else null
        }

        private fun parseInstant(text: String): Instant? =
            runCatching { Instant.parse(text) }.getOrNull()
                ?: runCatching { OffsetDateTime.parse(text).toInstant() }.getOrNull()

        private fun String.nullIfBlank(): String? = ifBlank { null }
    }
}
