package org.osservatorionessuno.libmvt.android.parsers

import org.apache.commons.compress.archivers.zip.ZipFile
import org.apache.commons.compress.utils.SeekableInMemoryByteChannel
import java.io.File
import java.io.InputStream

/**
 * ZIP reader that accepts STORED entries with a data descriptor.
 * JDK [java.util.zip.ZipInputStream] rejects those.
 *
 * [ZipFile] reads the central directory via a [java.nio.channels.SeekableByteChannel].
 * Streams are wrapped with [SeekableInMemoryByteChannel] to perform in-memory extraction.
 * 
 * https://commons.apache.org/proper/commons-compress/zip.html#ZipArchiveInputStream_vs_ZipFile
 */
internal class LenientZipInputStream private constructor(
    private val zip: ZipFile,
) : AutoCloseable {

    constructor(apk: File) : this(ZipFile(apk))

    constructor(apkBytes: ByteArray) : this(ZipFile(SeekableInMemoryByteChannel(apkBytes)))

    constructor(input: InputStream) : this(input.readBytes())

    fun fileNames(): Sequence<String> =
        zip.entries.asSequence().mapNotNull { entry ->
            if (entry.isDirectory) null else entry.name
        }

    fun readContent(name: String): ByteArray? {
        val entry = zip.getEntry(name) ?: return null
        return zip.getInputStream(entry).use { it.readBytes() }
    }

    override fun close() {
        zip.close()
    }
}
