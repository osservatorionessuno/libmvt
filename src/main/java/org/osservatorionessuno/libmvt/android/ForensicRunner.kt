package org.osservatorionessuno.libmvt.android

import org.osservatorionessuno.libmvt.android.artifacts.AndroidArtifact
import org.osservatorionessuno.libmvt.android.artifacts.DumpsysAdb
import org.osservatorionessuno.libmvt.common.AbstractInput
import org.osservatorionessuno.libmvt.common.Artifact
import org.osservatorionessuno.libmvt.common.Detection
import org.osservatorionessuno.libmvt.common.DetectionType
import org.osservatorionessuno.libmvt.common.Indicators
import org.osservatorionessuno.libmvt.common.ReopenableInput
import org.osservatorionessuno.libmvt.common.StringResolver
import org.osservatorionessuno.libmvt.common.logging.LogUtils
import java.io.File
import java.io.FileNotFoundException
import java.io.IOException
import java.io.InputStream
import java.util.LinkedHashMap
import java.util.concurrent.CancellationException
import java.util.zip.ZipFile
import java.util.zip.ZipInputStream

class ArtifactInput(
    path: String,
    inputStream: InputStream,
) : AbstractInput(path, inputStream)

/**
 * Placeholder for a path whose modules all failed, so the failure still reaches the report.
 * Not registered in [ArtifactModuleRegistry]; it only carries [Artifact.detected].
 */
private class SkippedArtifact : AndroidArtifact() {
    override fun paths(): List<String> = emptyList()

    override fun parse(artifactInput: AbstractInput) = Unit
}

/**
 * Simple helper to run the available AndroidQF artifact parsers on a folder
 * or zip containing extracted androidqf data.
 *
 * Axioms:
 * - Each module declares path patterns via [AndroidArtifact.paths] (exact or glob).
 * - Every matching module receives an [ArtifactInput]; only the module should read its stream.
 * - Custom stream sources use [ReopenableInput] so each module gets a fresh stream.
 * - A fresh module instance is created per parse; their findings are then merged.
 * - A module that throws is logged and reported, keeping what it found; the acquisition runs on.
 * - [SKIP_FILES] and paths under `tmp/` are ignored.
 * - Nested [BUGREPORT_ZIP] entries are expanded and analyzed like a zip archive.
 */
class ForensicRunner(private val stringResolver: StringResolver) {
    private var indicators: Indicators? = null
    private var adbHostKeys: List<String> = emptyList()

    /** Assign indicators to use for IOC matching. */
    fun setIndicators(indicators: Indicators?) {
        this.indicators = indicators
        this.indicators?.setStringResolver(stringResolver)
    }

    /**
     * Declare the acquiring host's own adb keys (adb_keys lines, e.g. adb_host_key.pub or the
     * acquisition's `adb_host_public_key`), reported as [DetectionType.ADB_HOST_FINGERPRINT]
     * instead of unknown-key detections.
     */
    fun setAdbHostKeys(keys: Collection<String>) {
        adbHostKeys = keys.toList()
    }

    /**
     * This is an insecure method to analyze a plaintext directory.
     * This should NOT be used in Bugbane, since it parses plaintext files.
     */
    @Throws(Exception::class)
    fun streamLegacyAnalysisFromDirectory(directory: File): Map<String, Artifact> {
        LogUtils.d(TAG, "streamLegacyAnalysisFromDirectory: $directory")
        val results = LinkedHashMap<String, Artifact>()
        collectFromDirectory(directory, directory, results)
        return results
    }

    /** This is a method to analyze a zip file. */
    @Throws(Exception::class)
    fun streamAnalysisFromZip(zip: File): Map<String, Artifact> {
        LogUtils.d(TAG, "streamAnalysisFromZip: $zip")
        val results = LinkedHashMap<String, Artifact>()
        try {
            ZipFile(zip).use { zipFile ->
                for (entry in zipFile.entries()) {
                    if (entry.isDirectory) continue
                    LogUtils.d(TAG, "Analyzing entry: ${entry.name}")
                    results.putAll(analyzeEntry(entry.name) { zipFile.getInputStream(entry) })
                }
            }
        } catch (e: IOException) {
            if (e is FileNotFoundException && zip.exists()) {
                throw IOException(
                    "Cannot read ${zip.absolutePath}: the file exists but access was denied.",
                    e,
                )
            }
            throw e
        }
        return results
    }

    /**
     * Analyze a single reopenable entry.
     * Normal files yield a 0–1 entry map; [BUGREPORT_ZIP] expands to nested results.
     */
    @Throws(Exception::class)
    fun streamFileAnalysis(entry: ReopenableInput): Map<String, Artifact> =
        analyzeEntry(entry.path) { entry.openStream() }

    /**
     * Expand a nested zip (e.g. bugreport) and analyze matching entries.
     * Result keys are `"$pathPrefix/${entry.name}"`.
     *
     * A first pass lists the entries a module asks for, then each is reopened on demand: a
     * bugreport is as large as the device wants it to be, so nothing here is held in memory.
     * A zip that cannot be listed to the end keeps the entries it did yield and reports the rest.
     */
    @Throws(Exception::class)
    private fun analyzeNestedZip(
        pathPrefix: String,
        openZip: () -> InputStream,
    ): Map<String, Artifact> {
        val wanted = LinkedHashSet<String>()
        var listingFailed = false
        try {
            ZipInputStream(openZip()).use { zis ->
                while (true) {
                    val entry = zis.nextEntry ?: break
                    val nestedName = entry.name.replace('\\', '/')
                    if (!entry.isDirectory && findModuleIndices(nestedName).isNotEmpty()) {
                        wanted.add(nestedName)
                    }
                    zis.closeEntry()
                }
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            if (Thread.currentThread().isInterrupted) throw e
            // A truncated bugreport costs the entries after the damage, not the acquisition.
            LogUtils.w(TAG, "Cannot list $pathPrefix: $e")
            listingFailed = true
        }
        LogUtils.d(TAG, "analyzeNestedZip: prefix=$pathPrefix entries=$wanted")

        val results = LinkedHashMap<String, Artifact>()
        for (nestedName in wanted) {
            analyzePath(nestedName) { openNestedEntry(openZip, nestedName) }?.let { artifact ->
                results["$pathPrefix/$nestedName"] = artifact
            }
        }
        if (listingFailed) {
            // Report the lost coverage, as analyzePath does for a module that throws.
            val carrier = SkippedArtifact()
            carrier.detected.add(
                Detection(DetectionType.ARTIFACT_PARSE_FAILED, pathPrefix, "nested zip"),
            )
            results[pathPrefix] = carrier
        }
        return results
    }

    /** Reopen the nested zip and hand back its stream positioned at [nestedName]. */
    @Throws(IOException::class)
    private fun openNestedEntry(openZip: () -> InputStream, nestedName: String): InputStream {
        val zis = ZipInputStream(openZip())
        while (true) {
            val entry = zis.nextEntry ?: break
            if (entry.name.replace('\\', '/') == nestedName) return zis
        }
        zis.close()
        throw IOException("$nestedName is no longer in the nested zip")
    }

    /**
     * If [path] is a bugreport zip, expand it; otherwise match modules via [analyzePath].
     */
    @Throws(Exception::class)
    private fun analyzeEntry(path: String, openStream: () -> InputStream): Map<String, Artifact> {
        val normalized = path.replace('\\', '/')
        if (isBugreportZip(normalized)) {
            LogUtils.d(TAG, "Expanding nested bugreport zip: $normalized")
            return analyzeNestedZip(normalized, openStream)
        }
        val artifact = analyzePath(normalized, openStream) ?: return emptyMap()
        return mapOf(normalized to artifact)
    }

    /**
     * Match [path] against registered modules and parse with a fresh stream from [openStream] per module.
     */
    @Throws(Exception::class)
    private fun analyzePath(path: String, openStream: () -> InputStream): Artifact? {
        if (shouldSkip(path)) {
            LogUtils.d(TAG, "Skipping path: $path")
            return null
        }

        val moduleIndices = try {
            ArtifactModuleRegistry.findModuleIndices(path)
        } catch (e: Exception) {
            LogUtils.w(TAG, "Cannot match modules for $path: $e")
            return null
        }
        if (moduleIndices.isEmpty()) {
            LogUtils.d(TAG, "No modules found for path: $path")
            return null
        }

        LogUtils.d(TAG, "analyzePath: $path -> modules $moduleIndices")

        var merged: AndroidArtifact? = null
        val failures = mutableListOf<Detection>()
        for (index in moduleIndices) {
            val module = ArtifactModuleRegistry.create(index)
            try {
                var parseError: Throwable? = null
                try {
                    openStream().use { stream ->
                        // Before parse: modules check each record as it is decoded, then drop it.
                        prepareArtifact(module)
                        module.parse(ArtifactInput(path, stream))
                    }
                } catch (e: Throwable) {
                    parseError = e
                    throw e
                } finally {
                    // Run even when parse throws: checkIndicators is where a module hands over
                    // detections it had to hold back for ordering, so skipping it loses them.
                    try {
                        module.checkIndicators()
                    } catch (e: Throwable) {
                        // The parse failure stays primary; a broken final pass must not mask it.
                        if (parseError == null) throw e else parseError.addSuppressed(e)
                    }
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                if (Thread.currentThread().isInterrupted) throw e
                // A truncated or malformed artifact drops its module, not the acquisition.
                LogUtils.w(TAG, "Skipping ${module.javaClass.simpleName} for $path: $e")
                // Path first: the CLI renders only the value, not the grouped file key.
                failures.add(Detection(DetectionType.ARTIFACT_PARSE_FAILED, path, module.javaClass.simpleName))
            }
            // Merged even on failure: records are checked as they stream, so the part that did
            // parse has already produced detections worth keeping.
            merged = mergeInto(merged, module)
        }

        if (failures.isEmpty()) {
            return merged
        }
        // Report the lost coverage: a missing detection here means "not analysed", not "clean".
        val carrier = merged ?: SkippedArtifact()
        carrier.detected.addAll(failures)
        return carrier
    }

    private fun shouldSkip(path: String): Boolean {
        val fileName = path.substringAfterLast('/')
        if (fileName in SKIP_FILES) {
            return true
        }
        if (path.startsWith("tmp/")) {
            return true
        }
        return false
    }

    private fun mergeInto(existing: AndroidArtifact?, parsed: AndroidArtifact): AndroidArtifact {
        if (existing == null) {
            return parsed
        }
        existing.merge(parsed)
        return existing
    }

    private fun prepareArtifact(artifact: AndroidArtifact) {
        artifact.stringResolver = stringResolver
        indicators?.let { ind ->
            ind.setStringResolver(stringResolver)
            artifact.indicators = ind
        }
        if (artifact is DumpsysAdb && adbHostKeys.isNotEmpty()) {
            artifact.setHostKeys(adbHostKeys)
        }
    }

    private fun collectFromDirectory(
        root: File,
        current: File,
        results: LinkedHashMap<String, Artifact>,
    ) {
        val files = current.listFiles() ?: return
        for (file in files) {
            when {
                file.isDirectory -> collectFromDirectory(root, file, results)
                file.isFile -> {
                    val relativePath = root.toPath()
                        .relativize(file.toPath())
                        .toString()
                        .replace('\\', '/')
                    results.putAll(analyzeEntry(relativePath) { file.inputStream() })
                }
            }
        }
    }

    companion object {
        private const val TAG = "ForensicRunner"

        @JvmStatic
        fun findModuleIndices(path: String): List<Int> =
            ArtifactModuleRegistry.findModuleIndices(path)

        @JvmStatic
        fun isBugreportZip(path: String): Boolean {
            val fileName = path.replace('\\', '/').substringAfterLast('/')
            return fileName.equals(BUGREPORT_ZIP, ignoreCase = true)
        }

        /** True if [path] is a nested bugreport zip or matches at least one module. */
        @JvmStatic
        fun isAnalyzable(path: String): Boolean =
            isBugreportZip(path) || findModuleIndices(path).isNotEmpty()

        /*
         * Files to skip when analyzing an aquisition.
         */
        @JvmField
        val SKIP_FILES: List<String> = listOf(
            "env.txt",
            "acquisition.json",
        )

        @JvmField
        val BUGREPORT_ZIP = "bugreport.zip"
    }
}
