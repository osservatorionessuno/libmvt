package org.osservatorionessuno.libmvt.android

import org.osservatorionessuno.libmvt.android.artifacts.*
import java.nio.file.FileSystems
import java.nio.file.Paths

/**
 * Registry of artifact parsers and their declared path patterns (exact or glob).
 */
object ArtifactModuleRegistry {

    private val factories: List<() -> AndroidArtifact> = listOf(
        // Bugreport modules
        { DumpsysAccessibility() },
        { DumpsysPackageActivities() },
        { DumpsysAdb() },
        { DumpsysAppops() },
        { DumpsysBatteryDaily() },
        { DumpsysBatteryHistory() },
        { DumpsysDBInfo() },
        { DumpsysPackages() },
        { DumpsysPlatformCompat() },
        { DumpsysReceivers() },
        { TombstoneCrashes() },
        { ANR() },
        // AndroidQF modules
        { Packages() },
        { Processes() },
        { GetProp() },
        { Settings() },
        { Files() },
        { SMS() },
        { RootBinaries() },
        { Mounts() },
        { SELinux() },
    )

    private val exactPatterns: List<Pair<String, Int>>
    private val globPatterns: List<Pair<String, Int>>

    init {
        val exact = mutableListOf<Pair<String, Int>>()
        val glob = mutableListOf<Pair<String, Int>>()
        for ((index, factory) in factories.withIndex()) {
            for (pattern in factory().paths()) {
                if (isGlobPattern(pattern)) {
                    glob.add(pattern to index)
                } else {
                    exact.add(pattern to index)
                }
            }
        }
        exactPatterns = exact
        globPatterns = glob
    }

    fun create(index: Int): AndroidArtifact = factories[index]()

    fun findModuleIndices(path: String): List<Int> {
        val normalizedPath = path.replace('\\', '/')
        val fileName = normalizedPath.substringAfterLast('/')
        val indices = LinkedHashSet<Int>()
        for ((pattern, index) in exactPatterns) {
            if (pattern == normalizedPath || pattern == fileName) {
                indices.add(index)
            }
        }
        for ((pattern, index) in globPatterns) {
            if (globMatches(pattern, normalizedPath) || globMatches(pattern, fileName)) {
                indices.add(index)
            }
        }
        return indices.toList()
    }

    private fun isGlobPattern(path: String): Boolean =
        path.any { it == '*' || it == '?' || it == '[' || it == '{' }

    private fun globMatches(pattern: String, path: String): Boolean =
        FileSystems.getDefault().getPathMatcher("glob:$pattern").matches(Paths.get(path))
}
