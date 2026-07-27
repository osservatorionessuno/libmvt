package org.osservatorionessuno

import org.json.JSONArray
import org.json.JSONObject
import org.osservatorionessuno.libmvt.common.logging.LogUtils
import org.osservatorionessuno.libmvt.android.AcquisitionMetadata
import org.osservatorionessuno.libmvt.android.ForensicRunner
import org.osservatorionessuno.libmvt.android.parsers.APKParser
import org.osservatorionessuno.libmvt.common.AlertLevel
import org.osservatorionessuno.libmvt.common.Artifact
import org.osservatorionessuno.libmvt.common.GroupedDetection
import org.osservatorionessuno.libmvt.common.Indicators
import org.osservatorionessuno.libmvt.common.IndicatorsUpdates
import org.osservatorionessuno.libmvt.common.JvmMapStringResolver
import java.io.File
import java.io.IOException
import java.nio.file.NoSuchFileException
import java.nio.file.Files
import java.nio.file.Path

object Main {

    private const val TAG = BuildInfo.NAME

    @JvmStatic
    fun main(args: Array<String>) {
        val exitCode = try {
            val cli = CliArgs.parseArgs(args)

            if (cli.updateIndicators) {
                IndicatorsUpdates().update()
                kotlin.system.exitProcess(0)
            }

            val inputPath: File = File(cli.inputPath)

            if (cli.analyzeAPK) {
                if (inputPath.isFile && inputPath.extension == "apk") {
                    analyzeAPK(inputPath)
                } else {
                    val apkFiles = inputPath.listFiles { file -> file.isFile && file.extension.equals("apk", ignoreCase = true) }
                    if (apkFiles != null && apkFiles.isNotEmpty()) {
                        apkFiles.forEach { analyzeAPK(it) }
                    } else {
                        println("No APK files found in directory: ${inputPath.absolutePath}")
                    }
                }
                0
            } else {
                val acquisition = AcquisitionMetadata.load(inputPath)
                if (!cli.json) {
                    printHeader(cli.indicatorsDir)
                }
                val detections = runAnalysis(cli)
                if (cli.json) {
                    printJsonDetections(detections, acquisition, cli.pretty)
                } else {
                    printDetections(detections, acquisition, cli.indicatorsDir)
                }
            }
            0
        } catch (e: CliArgs.CliException) {
            LogUtils.e(TAG, e.message)
            1
        } catch (e: NoSuchFileException) {
            LogUtils.e(TAG, "File not found: " + e.message)
            1
        } catch (e: IOException) {
            LogUtils.e(TAG, e.message)
            1
        } catch (e: Exception) {
            LogUtils.e(TAG, "Unexpected error: ${e.message}")
            e.printStackTrace(System.err)
            1
        }

        kotlin.system.exitProcess(exitCode)
    }

    private fun runAnalysis(cli: CliArgs.CliOptions): JSONArray {
        val indicators = loadIndicators(cli.indicatorsDir)

        val runner = ForensicRunner(JvmMapStringResolver()).apply {
            setIndicators(indicators)
        }

        val inputFile: File = File(cli.inputPath)
        val results: Map<String, Artifact> = when {
            inputFile.isDirectory -> runner.streamLegacyAnalysisFromDirectory(inputFile)
            inputFile.name.lowercase().endsWith(".zip") -> runner.streamAnalysisFromZip(inputFile)
            else -> throw CliArgs.CliException("Input must be a directory or a .zip file: ${cli.inputPath}")
        }

        return GroupedDetection.toJsonArray(
            GroupedDetection.fromArtifacts(results),
            JvmMapStringResolver(),
        )
    }

    private fun printHeader(indicatorsDir: Path) {
        println("${BuildInfo.NAME} ${BuildInfo.VERSION} analysis results")
        println()
        println("Indicators: $indicatorsDir")
        println()
    }

    private fun printDetections(
        groupedResults: JSONArray,
        acquisition: AcquisitionMetadata?,
        indicatorsDir: Path,
    ) {
        printAcquisitionMetadata(acquisition)
        
        val groups = (0 until groupedResults.length())
            .map { groupedResults.getJSONObject(it) }
            .filter { parseLevel(it.optString("level")) != AlertLevel.LOG }
            .sortedBy { parseLevel(it.optString("level")).level }

        if (groups.isEmpty()) {
            println("No detections.")
            println("Detections count: 0")
            return
        }

        if (groups.any { parseLevel(it.optString("level")) == AlertLevel.CRITICAL }) {
            println("WARNING: Critical indicators of compromise were found.")
            println()
        }

        groups.forEachIndexed { i, group ->
            if (i > 0) println()
            printGroup(group)
        }

        println()
        println("Detections count: ${groups.size}")
    }

    private fun printAcquisitionMetadata(acquisition: AcquisitionMetadata?) {
        if (acquisition == null) return
        acquisition.createdFormatted?.let { println("Created: $it") }
        acquisition.completedFormatted?.let { println("Completed: $it") }
        acquisition.bugbaneVersion?.let { println("Bugbane version: $it") } ?: run {
            acquisition.androidqfVersion?.let { println("AndroidQF version: $it") }
        }
        println()
    }

    private fun printGroup(group: JSONObject) {
        val values = group.optJSONArray("detections")?.let { detections ->
            (0 until detections.length()).mapNotNull { j ->
                jsonStringList(detections.getJSONObject(j).optJSONArray("value"))
            }
        } ?: emptyList()

        val title = group.optString("title").let { t ->
            if (values.size > 1) "$t (${values.size})" else t
        }
        println("[${group.optString("level").uppercase()}] $title")
        group.optString("context").takeIf { it.isNotEmpty() }?.let(::println)
        values.forEach { println("  • ${it.joinToString(", ")}") }
    }

    private fun jsonStringList(arr: JSONArray?): List<String>? {
        if (arr == null || arr.length() == 0) return null
        return List(arr.length()) { arr.optString(it) }
    }

    private fun parseLevel(name: String): AlertLevel =
        runCatching { AlertLevel.valueOf(name.uppercase()) }.getOrDefault(AlertLevel.INFO)

    private fun printJsonDetections(
        groupedResults: JSONArray,
        acquisition: AcquisitionMetadata?,
        pretty: Boolean,
    ) {
        val root = JSONObject()
        acquisition?.let { root.put("acquisition", it.toJsonObject()) }
        root.put("groupedResults", groupedResults)

        val json = if (pretty) root.toString(2) else root.toString()
        println(json)

        println("Detections count: ${groupedResults.length()}")
    }

    private fun loadIndicators(indicatorsDir: Path): Indicators {
        val indicators = Indicators()

        if (!Files.exists(indicatorsDir) || !Files.isDirectory(indicatorsDir)) {
            val hint =
                "Run with --update-indicators to download IOCs into ${CliArgs.defaultIndicatorsDir()}, " +
                    "or pass -i /path/to/iocs with .json/.stix2 files."
            throw CliArgs.CliException(
                "Indicators directory missing or not found: $indicatorsDir. $hint",
            )
        }

        indicators.loadFromDirectory(indicatorsDir.toFile())
        return indicators
    }

    private fun analyzeAPK(apkFile: File) {
        val apkInfo = APKParser.parseAPK(apkFile)
        val json = JSONObject().apply {
            put("packageName", apkInfo.packageName)
            put("versionCode", apkInfo.versionCode)
            put("versionName", apkInfo.versionName)
            put("certificateSubject", apkInfo.certificates)
        }
        println(json.toString(2))
    }
}
