package org.osservatorionessuno

import kotlinx.cli.ArgParser
import kotlinx.cli.ArgType
import kotlinx.cli.default
import kotlinx.cli.optional
import org.osservatorionessuno.libmvt.common.logging.LogUtils
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths

object CliArgs {

    private const val PROGRAM_NAME: String = BuildInfo.NAME
    private const val VERSION: String = BuildInfo.VERSION

    data class CliOptions(
        val indicatorsDir: Path?,
        val inputPath: Path,
        val updateIndicators: Boolean,
        val pretty: Boolean,
        val showVersion: Boolean,
        val analyzeAPK: Boolean,
    )

    class CliException(message: String) : RuntimeException(message)

    fun parseArgs(args: Array<String>): CliOptions {
        val parser = ArgParser(PROGRAM_NAME)

        val indicatorsDir by parser.option(
            ArgType.String,
            shortName = "i",
            fullName = "indicators",
            description = "Directory with .json/.stix2 indicator files",
        )

        val updateIndicators by parser.option(
            ArgType.Boolean,
            shortName = "u",
            fullName = "update-indicators",
            description = "Update indicators from the remote repository",
        ).default(false)

        val verbose by parser.option(
            ArgType.Boolean,
            shortName = "v",
            fullName = "verbose",
            description = "Print DEBUG-level logs",
        ).default(false)

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

        val analyzeAPK by parser.option(
            ArgType.Boolean,
            shortName = "a",
            fullName = "analyze-apk",
            description = "Analyze an APK file",
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

        LogUtils.setDebugEnabled(verbose)

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
            updateIndicators = updateIndicators,
            inputPath = resolvedInput,
            pretty = pretty,
            showVersion = showVersion,
            analyzeAPK = analyzeAPK,
        )
    }
}
