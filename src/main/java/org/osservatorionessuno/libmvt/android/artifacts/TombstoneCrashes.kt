package org.osservatorionessuno.libmvt.android.artifacts

import org.osservatorionessuno.libmvt.android.parsers.TombstoneProtobufParser
import org.osservatorionessuno.libmvt.common.AlertLevel
import org.osservatorionessuno.libmvt.common.AbstractInput
import org.osservatorionessuno.libmvt.common.Detection
import org.osservatorionessuno.libmvt.common.Indicators.IndicatorType

/**
 * Parser for Android tombstone crash files.
 * - Text format: always supported.
 * - Protobuf format: parsed via [TombstoneProtobufParser] (protobuf-javalite wire API).
 */
class TombstoneCrashes : AndroidArtifact() {

    override fun paths(): List<String> = listOf("**/tombstone*")

    override fun parse(artifactInput: AbstractInput) {
        results.clear()
        if (artifactInput.path.endsWith(".pb")) {
            parseProtobuf(artifactInput)
        } else {
            parseText(artifactInput)
        }
    }

    fun parseText(artifactInput: AbstractInput) {
        val rec = HashMap<String, Any?>()
        forEachLine(artifactInput.inputStream) { raw ->
            val line = raw.trim()
            when {
                line.startsWith("Timestamp:") -> {
                    rec["timestamp"] = normalizeTimestamp(line.substring("Timestamp:".length))
                }
                line.startsWith("Cmdline:") || line.startsWith("Cmd line:") -> {
                    val prefix = if (line.startsWith("Cmdline:")) "Cmdline:" else "Cmd line:"
                    val cmd = line.substring(prefix.length).trim()
                    rec["command_line"] = listOf(cmd)
                    extractPackageName(cmd)?.let { rec["package_name"] = it }
                }
                line.startsWith("uid:") -> {
                    line.substring("uid:".length).trim().toIntOrNull()?.let { rec["uid"] = it }
                }
                line.startsWith("pid:") -> {
                    // Example:
                    // pid: 25541, tid: 21307, name: mtk.ape.decoder  >>> /vendor/bin/hw/android.hardware.media.c2@1.2-mediatek <<<
                    val parts = line.split(",")
                    if (parts.size >= 3) {
                        parts[0].substringAfter(":").trim().toIntOrNull()?.let { rec["pid"] = it }
                        parts[1].substringAfter(":").trim().toIntOrNull()?.let { rec["tid"] = it }
                        var rest = parts[2].trim()
                        if (rest.startsWith("name:")) {
                            rest = rest.substring("name:".length).trim()
                            val nameParts = rest.split(">>>")
                            rec["process_name"] = nameParts[0].trim()
                            if (nameParts.size >= 2) {
                                val binaryPath = nameParts[1].trim().removeSuffix("<<<").trim()
                                if (binaryPath.isNotEmpty()) {
                                    rec["binary_path"] = binaryPath
                                    extractPackageName(binaryPath)?.let { rec["package_name"] = it }
                                }
                            }
                        }
                    }
                }
            }
        }
        if (rec.isNotEmpty()) results.add(rec)
    }

    fun parseProtobuf(artifactInput: AbstractInput) {
        try {
            val pb = TombstoneProtobufParser.parse(artifactInput.inputStream.readBytes())
            val rec = protobufToRecord(pb)
            if (rec.isNotEmpty()) results.add(rec)
        } catch (_: Exception) {
            // Malformed protobuf or unsupported schema revision.
        }
    }

    private fun protobufToRecord(pb: TombstoneProtobufParser.Parsed): HashMap<String, Any?> {
        val rec = HashMap<String, Any?>()
        if (pb.timestamp.isNotEmpty()) {
            rec["timestamp"] = normalizeTimestamp(pb.timestamp)
        }
        if (pb.commandLine.isNotEmpty()) {
            rec["command_line"] = ArrayList(pb.commandLine)
            pb.commandLine.firstOrNull()?.let { cmd ->
                extractPackageName(cmd)?.let { rec["package_name"] = it }
            }
        }
        if (pb.pid != 0) rec["pid"] = pb.pid
        if (pb.tid != 0) rec["tid"] = pb.tid
        if (pb.uid != 0) rec["uid"] = pb.uid

        pb.processName()?.let { rec["process_name"] = it }
        return rec
    }

    override fun checkIndicators() {
        if (indicators == null) return

        for (obj in results) {
            @Suppress("UNCHECKED_CAST")
            val map = obj as? Map<String, Any?> ?: continue
            matchProcessIndicators(map)

            val uid = when (val u = map["uid"]) {
                is Number -> u.toInt()
                is String -> u.toIntOrNull()
                else -> null
            }
            val proc = map["process_name"] as? String
            if (uid != null && (uid == 0 || uid == 1000 || uid == 2000)) {
                detected.add(
                    Detection(
                        AlertLevel.MEDIUM,
                        getString("mvt_tombstone_crashes_uid_title"),
                        String.format(
                            getString("mvt_tombstone_crashes_uid_message"),
                            proc ?: "",
                            uid,
                        ),
                    ),
                )
            }
        }
    }

    private fun matchProcessIndicators(map: Map<String, Any?>) {
        val proc = map["process_name"] as? String
        if (!proc.isNullOrEmpty()) {
            detected.addAll(indicators!!.matchString(proc, IndicatorType.PROCESS))
        }

        (map["package_name"] as? String)?.let { pkg ->
            detected.addAll(indicators!!.matchString(pkg, IndicatorType.APP_ID))
        }

        val cmdLineObj = map["command_line"]
        if (cmdLineObj is List<*>) {
            for (item in cmdLineObj) {
                val cmd = item?.toString() ?: continue
                extractPackageName(cmd)?.let { pkg ->
                    detected.addAll(indicators!!.matchString(pkg, IndicatorType.APP_ID))
                }
                if (cmd.contains('/')) {
                    detected.addAll(indicators!!.matchString(cmd, IndicatorType.FILE_PATH))
                    detected.addAll(
                        indicators!!.matchString(cmd.substringAfterLast('/'), IndicatorType.PROCESS),
                    )
                } else if (!cmd.contains('.')) {
                    detected.addAll(indicators!!.matchString(cmd, IndicatorType.PROCESS))
                }
            }
        }

        (map["binary_path"] as? String)?.let { path ->
            detected.addAll(indicators!!.matchString(path, IndicatorType.FILE_PATH))
            detected.addAll(
                indicators!!.matchString(path.substringAfterLast('/'), IndicatorType.PROCESS),
            )
        }
    }

    private fun normalizeTimestamp(raw: String): String {
        var ts = raw.trim().replace(Regex("[+-][0-9]{4}$"), "")
        val dot = ts.indexOf('.')
        if (dot >= 0) {
            var frac = ts.substring(dot + 1)
            if (frac.length > 6) frac = frac.substring(0, 6)
            ts = ts.substring(0, dot) + "." + frac
        }
        return ts
    }

    companion object {
        private fun extractPackageName(cmd: String): String? {
            if (cmd.isEmpty() || cmd.contains('/')) return null
            val base = cmd.substringBefore(':').trim()
            return base.takeIf { it.contains('.') }
        }
    }
}
