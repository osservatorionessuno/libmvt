package org.osservatorionessuno.libmvt.android.artifacts

import org.osservatorionessuno.libmvt.common.AbstractInput
import org.osservatorionessuno.libmvt.android.parsers.APKParser

/** Parser for APK files under apks/. */
class APK : AndroidArtifact() {
    override fun paths(): List<String> {
        return listOf("apks/*.apk")
    }

    override fun parse(artifactInput: AbstractInput) {
        emit(APKParser.parseAPK(artifactInput.inputStream))
    }

    // TODO: override checkRecord to check indicators
}