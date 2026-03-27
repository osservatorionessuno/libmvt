package org.osservatorionessuno

import org.json.JSONArray
import org.json.JSONObject
import org.osservatorionessuno.libmvt.android.ForensicRunner
import org.osservatorionessuno.libmvt.android.parsers.APKParser
import org.osservatorionessuno.libmvt.common.Artifact
import org.osservatorionessuno.libmvt.common.Indicators
import org.osservatorionessuno.libmvt.common.IndicatorsUpdates
import org.osservatorionessuno.libmvt.common.JvmMapStringResolver
import org.osservatorionessuno.libmvt.common.logging.LogUtils
import java.io.File
import java.nio.file.Files
import java.nio.file.Path

object Main {

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
            } else {
                if (inputPath.isDirectory) {
                    val detections = runAnalysis(cli)
                    printDetections(detections, cli.pretty)
                }
            }
            0
        } catch (e: CliArgs.CliException) {
            System.err.println(e.message)
            1
        } catch (e: Exception) {
            System.err.println("Unexpected error: ${e.message}")
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

        return buildDetectionsArray(results)
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

    private fun buildDetectionsArray(results: Map<String, Artifact>): JSONArray {
        val resultsArray = JSONArray()

        for ((fileName, artifact) in results) {
            for (det in artifact.detected) {
                val obj = JSONObject()
                obj.put("file", fileName)
                obj.put("level", det.level.name)
                obj.put("title", det.title)
                obj.put("context", det.context)
                resultsArray.put(obj)
            }
        }

        return resultsArray
    }

    private fun printDetections(detections: JSONArray, pretty: Boolean) {
        val root = JSONObject()
        root.put("detections", detections)

        val json = if (pretty) root.toString(2) else root.toString()
        println(json)
        
        println("Detections count: ${detections.length()}")
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
