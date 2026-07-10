package org.osservatorionessuno.libmvt.android.artifacts

abstract class DumpsysArtifact : AndroidArtifact() {

    override fun paths(): List<String> = DUMPSYS_PATHS

    companion object {
        @JvmField
        val DUMPSYS_PATHS: List<String> = listOf("dumpsys.txt", "bugreport-*.txt")
    }
}
