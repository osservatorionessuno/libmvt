package org.osservatorionessuno.libmvt.common

import org.osservatorionessuno.libmvt.common.logging.LogUtils
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.charset.StandardCharsets
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder

object NetworkUtils {
    /*
    * Download a resource from a given URL and return it as a string.
    */
    fun httpGetString(url: String, timeout: Int, headers: Map<String, String>? = null): String? {
        return httpGet(url, timeout, headers) { conn ->
            conn.inputStream.bufferedReader(StandardCharsets.UTF_8).use { it.readText() }
        }
    }

    /*
    * Download a resource from a given URL and save it to a file.
    */
    fun httpGetToFile(url: String, dest: Path, timeout: Int, headers: Map<String, String>? = null): Boolean {
        return httpGet(url, timeout, headers) { conn ->
            Files.createDirectories(dest.parent)
            conn.inputStream.use { input ->
                Files.copy(input, dest, StandardCopyOption.REPLACE_EXISTING)
            }
            true
        } ?: false
    }

    /**
     * GET over HTTPS; on success, consume the response body via [onOk].
     */
    private fun <T> httpGet(
        urlString: String,
        timeout: Int,
        headers: Map<String, String>?,
        onOk: (HttpURLConnection) -> T,
    ): T? {
        return try {
            val url = URL(urlString)
            require(url.protocol.equals("https", ignoreCase = true)) {
                "Only HTTPS URLs are allowed: $url"
            }
            val conn = url.openConnection() as HttpURLConnection
            conn.requestMethod = "GET"
            conn.connectTimeout = timeout
            conn.readTimeout = timeout
            conn.instanceFollowRedirects = true
            headers?.forEach { (k, v) -> conn.setRequestProperty(k, v) }
            val code = conn.responseCode
            if (code != HttpURLConnection.HTTP_OK) {
                logErrorBody(conn)
                conn.disconnect()
                return null
            }
            try {
                onOk(conn)
            } finally {
                conn.disconnect()
            }
        } catch (e: Exception) {
            LogUtils.e(NetworkUtils::class.java.name, "HTTP GET failed: $urlString", e)
            null
        }
    }

    fun urlEncode(s: String): String = URLEncoder.encode(s, StandardCharsets.UTF_8)

    fun logErrorBody(conn: HttpURLConnection) {
        conn.errorStream?.use { stream ->
            val body = stream.readBytes().toString(StandardCharsets.UTF_8)
            LogUtils.w(NetworkUtils::class.java.name, "Error body: $body")
        }
    }

}
