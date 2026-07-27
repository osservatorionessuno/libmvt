package org.osservatorionessuno.libmvt.android

import org.osservatorionessuno.libmvt.android.artifacts.AndroidArtifact
import org.osservatorionessuno.libmvt.common.AbstractInput
import org.osservatorionessuno.libmvt.common.Artifact
import org.osservatorionessuno.libmvt.common.Detection
import org.osservatorionessuno.libmvt.common.DetectionType
import org.osservatorionessuno.libmvt.common.Indicators
import org.osservatorionessuno.libmvt.common.ReopenableInput
import org.osservatorionessuno.libmvt.common.StringResolver
import org.osservatorionessuno.libmvt.common.logging.LogUtils
import java.io.ByteArrayInputStream
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

    override fun checkIndicators() = Unit
}

/**
 * Simple helper to run the available AndroidQF artifact parsers on a folder
 * or zip containing extracted androidqf data.
 *
 * Axioms:
 * - Each module declares path patterns via [AndroidArtifact.paths] (exact or glob).
 * - Every matching module receives an [ArtifactInput]; only the module should read its stream.
 * - Custom stream sources use [ReopenableInput] so each module gets a fresh stream.
 * - A fresh module instance is created per parse; results are then merged.
 * - A module that throws is dropped and logged; the rest of the acquisition still runs.
 * - [SKIP_FILES] and paths under `tmp/` are ignored.
 * - Nested [BUGREPORT_ZIP] entries are buffered in memory and analyzed like a zip archive.
 */
class ForensicRunner(private val stringResolver: StringResolver) {
    private var indicators: Indicators? = null

    /** Assign indicators to use for IOC matching. */
    fun setIndicators(indicators: Indicators?) {
        this.indicators = indicators
        this.indicators?.setStringResolver(stringResolver)
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
     * Expand an in-memory zip (e.g. nested bugreport) and analyze matching entries.
     * Result keys are `"$pathPrefix/${entry.name}"`.
     */
    @Throws(Exception::class)
    private fun streamAnalysisFromZipBytes(
        bytes: ByteArray,
        pathPrefix: String,
    ): Map<String, Artifact> {
        LogUtils.d(TAG, "streamAnalysisFromZipBytes: prefix=$pathPrefix size=${bytes.size}")
        val results = LinkedHashMap<String, Artifact>()
        ZipInputStream(ByteArrayInputStream(bytes)).use { zis ->
            while (true) {
                val entry = zis.nextEntry ?: break
                if (entry.isDirectory) {
                    zis.closeEntry()
                    continue
                }
                val entryBytes = zis.readBytes()
                zis.closeEntry()
                val nestedName = entry.name.replace('\\', '/')
                val resultKey = "$pathPrefix/$nestedName"
                analyzePath(nestedName) { ByteArrayInputStream(entryBytes) }?.let { artifact ->
                    results[resultKey] = artifact
                }
            }
        }
        return results
    }

    /**
     * If [path] is a bugreport zip, buffer and expand; otherwise match modules via [analyzePath].
     */
    @Throws(Exception::class)
    private fun analyzeEntry(path: String, openStream: () -> InputStream): Map<String, Artifact> {
        val normalized = path.replace('\\', '/')
        if (isBugreportZip(normalized)) {
            LogUtils.d(TAG, "Expanding nested bugreport zip: $normalized")
            val bytes = openStream().use { it.readBytes() }
            return streamAnalysisFromZipBytes(bytes, normalized)
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
                openStream().use { stream ->
                    // Before parse: streaming modules check each record as it is decoded.
                    prepareArtifact(module)
                    module.parse(ArtifactInput(path, stream))
                    module.checkIndicators()
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                if (Thread.currentThread().isInterrupted) throw e
                // A truncated or malformed artifact drops its module, not the acquisition.
                LogUtils.w(TAG, "Skipping ${module.javaClass.simpleName} for $path: $e")
                // Path first: the CLI renders only the value, not the grouped file key.
                failures.add(Detection(DetectionType.ARTIFACT_PARSE_FAILED, path, module.javaClass.simpleName))
                continue
            }
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
        existing.results.addAll(parsed.results)
        existing.detected.addAll(parsed.detected)
        return existing
    }

    private fun prepareArtifact(artifact: AndroidArtifact) {
        artifact.stringResolver = stringResolver
        indicators?.let { ind ->
            ind.setStringResolver(stringResolver)
            artifact.indicators = ind
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
