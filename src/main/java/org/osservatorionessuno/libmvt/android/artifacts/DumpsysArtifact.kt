package org.osservatorionessuno.libmvt.android.artifacts

abstract class DumpsysArtifact : AndroidArtifact() {

    override fun paths(): List<String> = DUMPSYS_PATHS

    companion object {
        @JvmField
        // dumpsys_<service>.txt: Bugbane sidecars when a required service was missing from the full dump.
        val DUMPSYS_PATHS: List<String> = listOf("dumpsys.txt", "dumpsys_*.txt", "bugreport-*.txt")
    }
}
