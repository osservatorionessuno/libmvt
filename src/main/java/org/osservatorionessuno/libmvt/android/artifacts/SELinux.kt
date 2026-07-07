package org.osservatorionessuno.libmvt.android.artifacts

import org.osservatorionessuno.libmvt.common.AbstractInput
import org.osservatorionessuno.libmvt.common.Detection
import org.osservatorionessuno.libmvt.common.DetectionType

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
            detected.add(Detection(DetectionType.SELINUX_STATUS, entry))
        }
    }
}