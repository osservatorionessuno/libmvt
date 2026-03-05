package org.osservatorionessuno.libmvt

import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.io.InputStream

object ResourcesUtils {

    @JvmStatic
    @Throws(IOException::class)
    fun readResourceBytes(name: String): ByteArray {
        val path: Path = Paths.get("src", "test", "resources", name)
        val bytes = Files.readAllBytes(path)
        return bytes
    }

    @JvmStatic
    @Throws(IOException::class)
    fun readResource(name: String): InputStream {
        val path: Path = Paths.get("src", "test", "resources", name)
        return Files.newInputStream(path)
    }
}

