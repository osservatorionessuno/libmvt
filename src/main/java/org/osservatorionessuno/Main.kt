package org.osservatorionessuno

import kotlinx.cli.ArgParser
import kotlinx.cli.ArgType
import kotlinx.cli.default
import kotlinx.cli.optional
import org.json.JSONArray
import org.json.JSONObject
import org.osservatorionessuno.libmvt.android.ForensicRunner
import org.osservatorionessuno.libmvt.common.Artifact
import org.osservatorionessuno.libmvt.common.Indicators
import org.osservatorionessuno.libmvt.common.JvmMapStringResolver
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths

object Main {

    private const val PROGRAM_NAME: String = BuildInfo.NAME
    private const val VERSION: String = BuildInfo.VERSION

    @JvmStatic
    fun main(args: Array<String>) {
        val exitCode = try {
            val cli = parseArgs(args)
            val detections = runAnalysis(cli)
            printDetections(detections, cli.pretty)
            0
        } catch (e: CliException) {
            System.err.println(e.message)
            1
        } catch (e: Exception) {
            System.err.println("Unexpected error: ${e.message}")
            e.printStackTrace(System.err)
            1
        }

        kotlin.system.exitProcess(exitCode)
    }

    private data class CliOptions(
        val indicatorsDir: Path?,
        val inputPath: Path,
        val pretty: Boolean,
        val showVersion: Boolean,
    )

    private class CliException(message: String) : RuntimeException(message)

    private fun parseArgs(args: Array<String>): CliOptions {
        val parser = ArgParser(PROGRAM_NAME)

        val indicatorsDir by parser.option(
            ArgType.String,
            shortName = "i",
            fullName = "indicators",
            description = "Directory with .json/.stix2 indicator files",
        )

        val pretty by parser.option(
            ArgType.Boolean,
            shortName = "p",
            fullName = "pretty",
            description = "Pretty-print JSON output",
        ).default(true)

        val showVersion by parser.option(
            ArgType.Boolean,
            shortName = "V",
            fullName = "version",
            description = "Print version and exit",
        ).default(false)

        val inputPathArg by parser.argument(
            ArgType.String,
            description = "AndroidQF output: extracted directory or .zip",
        ).optional()

        try {
            parser.parse(args)
        } catch (e: Exception) {
            throw CliException(e.message ?: "Invalid command-line arguments")
        }

        if (showVersion && inputPathArg == null) {
            println("$PROGRAM_NAME $VERSION")
            kotlin.system.exitProcess(0)
        }

        val inputPath = inputPathArg ?: throw CliException("Input path missing or not found")

        val resolvedInput = Paths.get(inputPath)
        if (!Files.exists(resolvedInput)) {
            throw CliException("Input path missing or not found: $resolvedInput")
        }

        return CliOptions(
            indicatorsDir = indicatorsDir?.let { Paths.get(it) },
            inputPath = resolvedInput,
            pretty = pretty,
            showVersion = showVersion,
        )
    }

    private fun runAnalysis(cli: CliOptions): JSONArray {
        val indicators = loadIndicators(cli.indicatorsDir)

        val runner = ForensicRunner(JvmMapStringResolver()).apply {
            setIndicators(indicators)
        }

        val inputFile: File = cli.inputPath.toFile()
        val results: Map<String, Artifact> = when {
            inputFile.isDirectory -> runner.streamLegacyAnalysisFromDirectory(inputFile)
            inputFile.name.lowercase().endsWith(".zip") -> runner.streamAnalysisFromZip(inputFile)
            else -> throw CliException("Input must be a directory or a .zip file: ${cli.inputPath}")
        }

        return buildDetectionsArray(results)
    }

    private fun loadIndicators(indicatorsDir: Path?): Indicators {
        val indicators = Indicators()

        if (indicatorsDir == null || !Files.exists(indicatorsDir) || !Files.isDirectory(indicatorsDir)) {
            throw CliException("Indicators directory missing or not found: $indicatorsDir")
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
}
