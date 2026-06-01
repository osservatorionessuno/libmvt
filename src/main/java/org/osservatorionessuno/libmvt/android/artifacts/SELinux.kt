package org.osservatorionessuno.libmvt.android.artifacts

import org.osservatorionessuno.libmvt.common.AlertLevel
import org.osservatorionessuno.libmvt.common.AbstractInput
import org.osservatorionessuno.libmvt.common.Detection

/** Parser for SELinux status files. */
class SELinux : AndroidArtifact() {
    override fun paths(): List<String> {
        return listOf("selinux.txt")
    }

    override fun parse(artifactInput: AbstractInput) {
        results.clear()
        val status = collectText(artifactInput.inputStream).trim().lowercase()
        val map = mutableMapOf<String, String>()
        map["status"] = status
        results.add(map)
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