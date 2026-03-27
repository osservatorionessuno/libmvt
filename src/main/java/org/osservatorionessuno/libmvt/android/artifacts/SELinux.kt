package org.osservatorionessuno.libmvt.android.artifacts

import org.osservatorionessuno.libmvt.common.AlertLevel
import org.osservatorionessuno.libmvt.common.Detection
import java.io.InputStream

/** Parser for SELinux status files. */
class SELinux : AndroidArtifact() {
    override fun paths(): List<String> {
        return listOf("selinux.txt")
    }

    override fun parse(input: InputStream) {
        results.clear()
        if (input != null) {
            val status = collectText(input).trim().lowercase()
            val map = mutableMapOf<String, String>()
            map["status"] = status
            results.add(map)
        }
    }

    override fun checkIndicators() {
        if (results.isEmpty()) return
        @Suppress("UNCHECKED_CAST")
        val statusMap = results[0] as? Map<String, String> ?: return
        val entry = statusMap["status"] ?: ""
        if (entry != "enforcing") {
            detected.add(
                Detection(
                    AlertLevel.HIGH,
                    getString("mvt_selinux_status_title"),
                    String.format(
                        getString("mvt_selinux_status_message"),
                        entry
                    )
                )
            )
        }
    }
}