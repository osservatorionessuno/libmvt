package org.osservatorionessuno.libmvt.android.artifacts

import org.osservatorionessuno.libmvt.common.Artifact
import org.osservatorionessuno.libmvt.common.StringResolver
import java.io.InputStream
import java.io.IOException
import java.io.ByteArrayInputStream

abstract class AndroidArtifact : Artifact() {

    var stringResolver: StringResolver? = null
        @JvmName("setStringResolver") set


    protected fun getString(name: String): String =
        stringResolver?.get(name) ?: ""

    abstract fun paths(): List<String>

    @Throws(IOException::class)
    protected fun collectText(content: InputStream): String {
        return content.bufferedReader(Charsets.UTF_8).use { it.readText() }
    }

    @Throws(IOException::class)
    protected fun collectLines(content: InputStream): List<String> {
        return content.bufferedReader(Charsets.UTF_8).useLines { it.toList() }
    }
}
