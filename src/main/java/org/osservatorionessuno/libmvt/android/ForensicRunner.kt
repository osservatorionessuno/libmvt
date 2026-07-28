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
import java.io.File
import java.io.InputStream
import java.util.LinkedHashMap
import java.util.concurrent.CancellationException
import java.util.zip.ZipFile

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
        ZipFile(zip).use { zipFile ->
            for (entry in zipFile.entries()) {
                analyzePath(entry.name) { zipFile.getInputStream(entry) }?.let { artifact ->
                    results[entry.name] = artifact
                }
            }
        }
        return results
    }

    /** Analyze entries from a custom source (e.g. encrypted container). */
    @Throws(Exception::class)
    fun streamAnalysis(entries: Iterable<ReopenableInput>): Map<String, Artifact> {
        LogUtils.d(TAG, "streamAnalysis: $entries")
        val results = LinkedHashMap<String, Artifact>()
        for (entry in entries) {
            analyzePath(entry.path) { entry.openStream() }?.let { artifact ->
                results[entry.path] = artifact
            }
        }
        return results
    }

    @Throws(Exception::class)
    fun streamFileAnalysis(entry: ReopenableInput): Artifact? =
        analyzePath(entry.path) { entry.openStream() }

    /**
     * Match [path] against registered modules and parse with a fresh stream from [openStream] per module.
     */
    @Throws(Exception::class)
    private fun analyzePath(path: String, openStream: () -> InputStream): Artifact? {
        if (shouldSkip(path)) {
            return null
        }

        val moduleIndices = try {
            ArtifactModuleRegistry.findModuleIndices(path)
        } catch (e: Exception) {
            LogUtils.w(TAG, "Cannot match modules for $path: $e")
            return null
        }
        if (moduleIndices.isEmpty()) {
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
            LogUtils.d(TAG, "Skipping file: $fileName")
            return true
        }
        if (path.startsWith("tmp/")) {
            LogUtils.d(TAG, "Skipping temporary file: $path")
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
                    analyzePath(relativePath) { file.inputStream() }?.let { artifact ->
                        results[relativePath] = artifact
                    }
                }
            }
        }
    }

    companion object {
        private const val TAG = "ForensicRunner"

        @JvmStatic
        fun findModuleIndices(path: String): List<Int> =
            ArtifactModuleRegistry.findModuleIndices(path)

        /* 
         * Files to skip when analyzing an aquisition.
         */
        @JvmField
        val SKIP_FILES: List<String> = listOf(
            "env.txt",
            "acquisition.json",
        )
    }
}
