package org.osservatorionessuno.libmvt.android.artifacts

import org.osservatorionessuno.libmvt.common.AbstractInput
import org.osservatorionessuno.libmvt.common.Detection
import org.osservatorionessuno.libmvt.common.Indicators.IndicatorType
import org.osservatorionessuno.libmvt.common.logging.LogUtils
import org.osservatorionessuno.libmvt.common.DetectionType

/**
 * Parser for Android ANR files.
 */
class ANR : AndroidArtifact() {

    override fun paths(): List<String> = listOf("**/anr_*")

    override fun parse(artifactInput: AbstractInput) {
        results.clear()
        LogUtils.d("ANR", "Parsing ANR file: ${artifactInput.path}")

        var subject: String? = null
        var current: HashMap<String, Any?>? = null

        fun flushCurrent() {
            val rec = current ?: return
            if (rec.isEmpty()) return
            subject?.let { rec["subject"] = it }
            results.add(rec)
            current = null
        }

        forEachLine(artifactInput.inputStream) { raw ->
            val line = raw.trim()
            when {
                line.startsWith("Subject:") -> {
                    subject = line.substring("Subject:".length).trim()
                }
                PID_HEADER.matches(line) -> {
                    flushCurrent()
                    val (pid, timestamp) = PID_HEADER.find(line)!!.destructured
                    current = hashMapOf(
                        "pid" to pid.toInt(),
                        "timestamp" to normalizeTimestamp(timestamp),
                    )
                }
                line.startsWith("Cmd line:") && current != null -> {
                    val cmd = line.substring("Cmd line:".length).trim()
                    current!!["command_line"] = listOf(cmd)
                    current!!["package_name"] = cmd
                }
            }
        }
        flushCurrent()
    }

    override fun checkIndicators() {
        if (indicators == null) return

        for (obj in results) {
            @Suppress("UNCHECKED_CAST")
            val map = obj as? Map<String, Any?> ?: continue

            val pkg = map["package_name"] as? String
            if (!pkg.isNullOrEmpty()) {
                detected.addAll(indicators!!.matchString(pkg, IndicatorType.APP_ID))
            }

            val cmdLineObj = map["command_line"]
            if (cmdLineObj is List<*> && cmdLineObj.isNotEmpty()) {
                val cmd = cmdLineObj[0]?.toString() ?: ""
                val slash = cmd.lastIndexOf('/')
                val name = if (slash >= 0) cmd.substring(slash + 1) else cmd
                detected.addAll(indicators!!.matchString(name, IndicatorType.PROCESS))
            }

            detected.add(Detection(DetectionType.ANR, pkg ?: ""))
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
        private val PID_HEADER =
            Regex("^----- pid (\\d+) at (.+) -----$")
    }
}
