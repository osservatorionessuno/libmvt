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
        val status = collectText(artifactInput.inputStream).trim().lowercase()
        emit(mapOf("status" to status))
    }

    override fun checkRecord(record: Any) {
        @Suppress("UNCHECKED_CAST")
        val status = (record as? Map<String, String>)?.get("status") ?: ""
        if (status != "enforcing") {
            detected.add(Detection(DetectionType.SELINUX_STATUS, status))
        }
    }
}