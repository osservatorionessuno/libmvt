package org.osservatorionessuno.libmvt.android.artifacts

import org.osservatorionessuno.libmvt.android.parsers.TombstoneProtobufParser
import org.osservatorionessuno.libmvt.common.AbstractInput
import org.osservatorionessuno.libmvt.common.Detection
import org.osservatorionessuno.libmvt.common.DetectionType
import org.osservatorionessuno.libmvt.common.Indicators.IndicatorType

/**
 * Parser for Android tombstone crash files.
 * - Text format: always supported.
 * - Protobuf format: parsed via [TombstoneProtobufParser] (protobuf-javalite wire API).
 *
 * BEWARE: "process_name" contains the 15-char truncated thread name (e.g. android.hardwar),
 * and is not the name of the process. Use "binary_path" instead.
 */
class TombstoneCrashes : AndroidArtifact() {

    override fun paths(): List<String> = listOf("**/tombstone*")

    override fun parse(artifactInput: AbstractInput) {
        if (artifactInput.path.endsWith(".pb")) {
            parseProtobuf(artifactInput)
        } else {
            parseText(artifactInput)
        }
    }

    fun parseText(artifactInput: AbstractInput) {
        val rec = HashMap<String, Any?>()
        // Only the first thread is the crashing thread.
        var sawCrashPidLine = false
        var inOpenFiles = false
        var inBacktrace = false
        val referencedFiles = linkedSetOf<String>()
        forEachLine(artifactInput.inputStream) { raw ->
            val line = raw.trim()
            when {
                line.startsWith("Timestamp:") -> {
                    inOpenFiles = false
                    inBacktrace = false
                    rec["timestamp"] = normalizeTimestamp(line.substring("Timestamp:".length))
                }
                line.startsWith("Cmdline:") || line.startsWith("Cmd line:") -> {
                    inOpenFiles = false
                    inBacktrace = false
                    val prefix = if (line.startsWith("Cmdline:")) "Cmdline:" else "Cmd line:"
                    val cmd = line.substring(prefix.length).trim()
                    rec["command_line"] = listOf(cmd)
                    extractPackageName(cmd)?.let { rec["package_name"] = it }
                }
                line.startsWith("uid:") -> {
                    inOpenFiles = false
                    inBacktrace = false
                    line.substring("uid:".length).trim().toIntOrNull()?.let { rec["uid"] = it }
                }
                line.startsWith("pid:") && !sawCrashPidLine -> {
                    inOpenFiles = false
                    inBacktrace = false
                    parsePidLine(line, rec)
                    sawCrashPidLine = true
                }
                line.equals("open files:", ignoreCase = true) -> {
                    inOpenFiles = true
                    inBacktrace = false
                }
                line.equals("backtrace:", ignoreCase = true) -> {
                    inBacktrace = true
                    inOpenFiles = false
                }
                inOpenFiles -> {
                    val path = parseOpenFileLine(line)
                    if (path != null) {
                        referencedFiles.add(path)
                    } else if (line.isNotEmpty()) {
                        inOpenFiles = false
                    }
                }
                inBacktrace -> {
                    val path = parseBacktraceFramePath(line)
                    if (path != null) {
                        referencedFiles.add(path)
                    } else if (line.isNotEmpty()) {
                        inBacktrace = false
                    }
                }
            }
        }
        if (referencedFiles.isNotEmpty()) {
            rec["referenced_files"] = referencedFiles
        }
        if (rec.isNotEmpty()) emit(rec)
    }

    fun parseProtobuf(artifactInput: AbstractInput) {
        try {
            val pb = TombstoneProtobufParser.parse(artifactInput.inputStream.readBytes())
            val rec = protobufToRecord(pb)
            if (rec.isNotEmpty()) emit(rec)
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
                rec.putIfAbsent("binary_path", cmd)
                extractPackageName(cmd)?.let { rec["package_name"] = it }
            }
        }
        if (pb.pid != 0) rec["pid"] = pb.pid
        if (pb.tid != 0) rec["tid"] = pb.tid
        if (pb.uid != 0) rec["uid"] = pb.uid

        pb.processName()?.let { rec["process_name"] = it }
        if (pb.referencedFiles.isNotEmpty()) {
            rec["referenced_files"] = LinkedHashSet(pb.referencedFiles)
        }
        return rec
    }

    override fun checkRecord(record: Any) {
        if (indicators == null) return

        @Suppress("UNCHECKED_CAST")
        val map = record as? Map<String, Any?> ?: return
        matchProcessIndicators(map)

        val uid = when (val u = map["uid"]) {
            is Number -> u.toInt()
            is String -> u.toIntOrNull()
            else -> null
        }
        if (uid != null && (uid == 0 || uid == 1000 || uid == 2000)) {
            detected.add(
                Detection(
                    DetectionType.TOMBSTONE_CRASHES_UID,
                    crashLabel(map),
                    uid.toString(),
                    (map["timestamp"] as? String).orEmpty(),
                ),
            )
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

        @Suppress("UNCHECKED_CAST")
        val referenced = map["referenced_files"] as? Collection<*>
        if (referenced != null) {
            for (item in referenced) {
                val path = item?.toString()?.takeIf { it.isNotEmpty() } ?: continue
                detected.addAll(indicators!!.matchString(path, IndicatorType.FILE_PATH))
            }
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
        /**
         * Prefer the executable/cmdline basename.
         */
        @JvmStatic
        fun crashLabel(map: Map<String, Any?>): String {
            basenameOf(map["binary_path"] as? String)?.let { return it }
            val cmd = (map["command_line"] as? List<*>)?.firstOrNull()?.toString()
            basenameOf(cmd)?.let { return it }
            return (map["package_name"] as? String).orEmpty()
        }

        private fun basenameOf(path: String?): String? {
            if (path.isNullOrBlank()) return null
            val base = path.substringAfterLast('/').trim()
            return base.takeIf { it.isNotEmpty() }
        }

        @JvmStatic
        fun parsePidLine(line: String, rec: MutableMap<String, Any?>) {
            // Example (legacy):
            // pid: 25541, tid: 21307, name: mtk.ape.decoder  >>> /vendor/bin/... <<<
            // Example (newer, with ppid):
            // pid: 1348, ppid: 1, tid: 1910, name: android.hardwar  >>> /vendor/bin/... <<<
            val parts = if (line.contains(" >>> ")) {
                line.split(" >>> ", limit = 2)
            } else {
                line.split(">>>", limit = 2)
            }
            val processInfo = parts[0]
            for (info in processInfo.split(",")) {
                val idx = info.indexOf(':')
                if (idx < 0) continue
                val key = info.substring(0, idx).trim()
                val value = info.substring(idx + 1).trim()
                when (key) {
                    "pid" -> value.toIntOrNull()?.let { rec["pid"] = it }
                    "tid" -> value.toIntOrNull()?.let { rec["tid"] = it }
                    "name" -> if (value.isNotEmpty()) rec["process_name"] = value
                }
            }
            if (parts.size >= 2) {
                val binaryPath = parts[1].trim().removeSuffix("<<<").trim()
                if (binaryPath.isEmpty()) {
                    throw IllegalArgumentException("binaryPath is empty")
                }
                rec["binary_path"] = binaryPath
                extractPackageName(binaryPath)?.let { rec["package_name"] = it }
            }
        }

        /** `fd 5: /dev/goodix_fp (unowned)` → `/dev/goodix_fp` (also strips ` (deleted)`). */
        @JvmStatic
        fun parseOpenFileLine(line: String): String? {
            val trimmed = line.trim()
            if (!trimmed.startsWith("fd ")) return null
            val colon = trimmed.indexOf(':')
            if (colon < 0) return null
            val after = trimmed.substring(colon + 1).trimStart()
            if (after.isEmpty()) return null
            // Drop ownership / "(deleted)" suffix after the path.
            val space = after.indexOf(' ')
            return if (space < 0) after else after.substring(0, space)
        }

        /** `#00 pc 0004bd80  /apex/.../libc.so (...)` → `/apex/.../libc.so` */
        @JvmStatic
        fun parseBacktraceFramePath(line: String): String? {
            val parts = line.trim().split(' ').filter { it.isNotEmpty() }
            // #NN pc <addr> <path> ...
            if (parts.size < 4) return null
            if (!parts[0].startsWith("#") || parts[1] != "pc") return null
            return parts[3]
        }

        private fun extractPackageName(cmd: String): String? {
            if (cmd.isEmpty() || cmd.contains('/')) return null
            val base = cmd.substringBefore(':').trim()
            return base.takeIf { it.contains('.') }
        }
    }
}
