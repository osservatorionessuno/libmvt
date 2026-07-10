package org.osservatorionessuno.libmvt.android.artifacts

import org.osservatorionessuno.libmvt.common.Artifact
import org.osservatorionessuno.libmvt.common.StringResolver
import java.io.InputStream
import java.io.IOException
import java.util.function.Consumer

abstract class AndroidArtifact : Artifact() {

    var stringResolver: StringResolver? = null
        @JvmName("setStringResolver") set


    protected fun getString(name: String): String =
        stringResolver?.get(name) ?: ""

    abstract fun paths(): List<String>

    @Deprecated("Use forEachLine instead")
    @Throws(IOException::class)
    protected fun collectText(content: InputStream): String {
        return content.bufferedReader(Charsets.UTF_8).use { it.readText() }
    }

    @Deprecated("Use forEachLine instead")
    @Throws(IOException::class)
    protected fun collectLines(content: InputStream): List<String> {
        return content.bufferedReader(Charsets.UTF_8).useLines { it.toList() }
    }
        
    @Throws(Exception::class)
    protected fun parseByExtension(
        artifactInput: org.osservatorionessuno.libmvt.common.AbstractInput,
        pb: StreamParser,
        json: StreamParser,
    ) {
        when {
            artifactInput.path.endsWith(".pb") -> pb.parse(artifactInput.inputStream)
            artifactInput.path.endsWith(".json") -> json.parse(artifactInput.inputStream)
            else -> throw IOException("Unsupported file type: ${artifactInput.path}")
        }
    }

    fun interface StreamParser {
        @Throws(Exception::class)
        fun parse(input: InputStream)
    }

    // Kotlin version of forEachLine
    @Throws(IOException::class)
    protected fun forEachLine(content: InputStream, block: (String) -> Unit) {
        content.bufferedReader(Charsets.UTF_8).useLines { lines ->
            lines.forEach(block)
        }
    }

    // Java 8 compatible version of forEachLine
    @Throws(IOException::class)
    protected fun forEachLine(content: InputStream, block: Consumer<String>) {
        forEachLine(content) { block.accept(it) }
    }

    /**
     * Invokes [block] for each line in a dumpsys section starting at [startPrefix]
     * until the 79-dash delimiter. Returns whether the section was found.
     */
    @Throws(IOException::class)
    protected fun extractDumpsysSection(content: InputStream, startPrefix: String, block: Consumer<String>): Boolean {
        var inSection = false
        content.bufferedReader(Charsets.UTF_8).useLines { lines ->
            for (line in lines) {
                if (!inSection) {
                    if (line.trimStart().startsWith("DUMP OF SERVICE ") &&
                        line.contains(startPrefix)
                    ) {
                        inSection = true
                        block.accept(line)
                    }
                } else {
                    if (line.contains("-".repeat(79))) {
                        break
                    }
                    block.accept(line)
                }
            }
        }
        return inSection
    }

    // Kotlin version of extractDumpsysSection
    @Throws(IOException::class)
    protected fun extractDumpsysSection(content: InputStream, startPrefix: String, block: (String) -> Unit): Boolean {
        return extractDumpsysSection(content, startPrefix, Consumer { block(it) })
    }
}
