package org.osservatorionessuno.libmvt.common

import org.json.JSONArray
import org.json.JSONObject
import org.json.JSONTokener
import org.osservatorionessuno.libmvt.common.logging.LogUtils
import java.io.IOException
import java.net.URI
import java.nio.charset.StandardCharsets
import java.time.Instant
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.StandardCopyOption

class IndicatorsUpdates @JvmOverloads constructor(
    dataFolder: Path? = null,
    private val sourceUrls: List<String> = emptyList(),
) {
    private val latestUpdatePath: Path
    private val latestCheckPath: Path
    private val indicatorsFolder: Path
    private val indicatorsSources: MutableList<String> = mutableListOf()

    companion object {
        @JvmField
        val MVT_DATA_FOLDER: Path = Paths.get(System.getProperty("user.home"), ".mvt")

        private const val INDICATORS_CHECK_FREQUENCY = 12 // in hours
        private const val TAG = "IndicatorsUpdates"
    }

    init {
        val base = dataFolder ?: MVT_DATA_FOLDER
        latestUpdatePath = base.resolve("latest_indicators_update")
        latestCheckPath = base.resolve("latest_indicators_check")
        indicatorsFolder = base.resolve("iocs")
        
        if (sourceUrls.isEmpty()) {
            // Add default sources
            indicatorsSources.addAll(defaultSourceUrls())
        } else {
            indicatorsSources.addAll(sourceUrls)
        }

        runCatching { Files.createDirectories(base) }
        runCatching { Files.createDirectories(indicatorsFolder) }

        LogUtils.i(
            TAG,
            "Updating indicators in $indicatorsFolder from ${indicatorsSources.size} sources",
        )
    }

    fun getIndicatorsFolder(): Path = indicatorsFolder

    private fun defaultSourceUrls(): List<String> = listOf(
        String.format(DEFAULT_GITHUB_RAW, "mvt-project", "mvt-indicators", "main", "indicators.yaml")
    )

    private fun githubLatestCommitEpoch(owner: String, repo: String, branch: String, path: String): Long {
        var t = githubLatestCommitEpochOnce(owner, repo, branch, path)
        if (t > 0) return t
        if (branch != "main") {
            LogUtils.d(TAG, "githubLatestCommitEpoch: retrying with branch=main")
            t = githubLatestCommitEpochOnce(owner, repo, "main", path)
            if (t > 0) return t
        }
        if (branch != "master") {
            LogUtils.d(TAG, "githubLatestCommitEpoch: retrying with branch=master")
            t = githubLatestCommitEpochOnce(owner, repo, "master", path)
            if (t > 0) return t
        }
        return 0L
    }

    private fun githubLatestCommitEpochOnce(owner: String, repo: String, branch: String, path: String): Long {
        return try {
            val apiUrl = buildString {
                append("https://api.github.com/repos/")
                append(NetworkUtils.urlEncode(owner)).append('/').append(NetworkUtils.urlEncode(repo))
                append("/commits?path=").append(NetworkUtils.urlEncode(path))
                append("&sha=").append(NetworkUtils.urlEncode(branch))
                append("&per_page=1")
            }
            val headers = mapOf(
                "Accept" to "application/vnd.github+json",
                "User-Agent" to "libmvt/1.0",
            )
            val body = NetworkUtils.httpGetString(apiUrl, 15_000, headers) ?: return 0L
            if (body.isEmpty()) {
                LogUtils.w(TAG, "githubLatestCommitEpochOnce: empty response for $owner/$repo@$branch path=$path")
                return 0L
            }
            val iso = extractFirstIsoDateFromCommits(body) ?: return 0L
            val epoch = Instant.parse(iso).epochSecond
            LogUtils.d(TAG, "githubLatestCommitEpochOnce: $owner/$repo@$branch path=$path -> $iso ($epoch)")
            epoch
        } catch (e: Exception) {
            LogUtils.w(TAG, "githubLatestCommitEpochOnce failed: $e")
            0L
        }
    }

    private fun extractFirstIsoDateFromCommits(json: String): String? {
        return try {
            when (val parsed = JSONTokener(json).nextValue()) {
                is JSONArray -> {
                    if (parsed.length() == 0) return null
                    parsed.getJSONObject(0)
                        .optJSONObject("commit")
                        ?.optJSONObject("author")
                        ?.optString("date", null)
                }
                is JSONObject -> {
                    val msg = parsed.optString("message", "")
                    if (msg.isNotEmpty()) LogUtils.w(TAG, "GitHub API message: $msg")
                    null
                }
                else -> null
            }
        } catch (_: Exception) {
            null
        }
    }

    @Throws(IOException::class)
    private fun downloadRemoteIoc(url: String): String? {
        Files.createDirectories(indicatorsFolder)
        val fileName = url.replaceFirst("^https?://".toRegex(), "").replace(Regex("[/\\\\]"), "_")
        val dest = indicatorsFolder.resolve(fileName)
        LogUtils.d(TAG, "Downloading IOC url=$url -> $dest")
        if (url.startsWith("file://")) {
            val p = Paths.get(URI.create(url))
            Files.copy(p, dest, StandardCopyOption.REPLACE_EXISTING)
            LogUtils.d(TAG, "Copied local IOC $p -> $dest")
            return dest.toString()
        }
        return if (NetworkUtils.httpGetToFile(url, dest, 15_000)) {
            dest.toString()
        } else {
            LogUtils.w(TAG, "Failed to download IOC: $url")
            null
        }
    }

    fun countIndicators(): Long = try {
        Files.list(indicatorsFolder).use { s ->
            s.count().also { LogUtils.d(TAG, "countIndicators folder=$indicatorsFolder count=$it") }
        }
    } catch (e: Exception) {
        LogUtils.e(TAG, "countIndicators failed for $indicatorsFolder", e)
        0L
    }

    fun getLatestCheck(): Long = try {
        Files.readString(latestCheckPath, StandardCharsets.UTF_8).trim().toLong()
    } catch (e: Exception) {
        LogUtils.d(TAG, "first getLatestCheck, returning 0")
        0L
    }

    private fun setLatestCheck() {
        try {
            val now = Instant.now().epochSecond
            Files.createDirectories(latestCheckPath.parent)
            Files.writeString(latestCheckPath, now.toString(), StandardCharsets.UTF_8)
        } catch (_: Exception) {
            LogUtils.w(TAG, "setLatestCheck failed")
        }
    }

    fun getLatestUpdate(): Long = try {
        Files.readString(latestUpdatePath, StandardCharsets.UTF_8).trim().toLong()
    } catch (e: Exception) {
        LogUtils.d(TAG, "first getLatestUpdate, returning 0")
        0L
    }

    private fun setLatestUpdate() {
        try {
            val now = Instant.now().epochSecond
            Files.createDirectories(latestUpdatePath.parent)
            Files.writeString(latestUpdatePath, now.toString(), StandardCharsets.UTF_8)
        } catch (_: Exception) {
            LogUtils.w(TAG, "setLatestUpdate failed")
        }
    }

    /*
     * Helper function to determine if we should perform an IOCs update check.
     * 
     * Returns true if no previous check has been performed or
     * if the latest check was more than INDICATORS_CHECK_FREQUENCY hours ago.
     */
    fun shouldUpdate(): Boolean {
        val latestCheck = getLatestCheck()
        if (latestCheck == 0L) { return true }

        val now = Instant.now().epochSecond
        val diff = now - latestCheck
        return diff >= INDICATORS_CHECK_FREQUENCY
    }
    
    /*
     * Perform an IOCs update check right now.
     * Use `shouldUpdate()` to determine if an update is needed.
     */
    @Throws(IOException::class)
    fun update() {
        setLatestCheck()

        val latestUpdate = getLatestUpdate()
        var attempted = 0; var succeeded = 0; var loadedAnySource = false

        // First we cycle through all the sources
        for (sourceUrl in indicatorsSources) {
            // We load the sources and fetch the indicators URLs they define
            val items = IndicatorsSource(sourceUrl)
            if (items.isEmpty()) {
                LogUtils.w(TAG, "update() skipping failed source: $sourceUrl")
                continue
            }

            loadedAnySource = true
            // For every indicator URLs we check if we need to download it
            for (item in items) {
                val plan = buildDownloadPlan(item, latestUpdate)
                if (plan.none { it.changed }) {
                    LogUtils.d(TAG, "No updates for source $sourceUrl")
                    continue
                }
                // Finally we download the updated STIX2 indicators
                for (ip in plan) {
                    if (!ip.changed) continue
                    attempted++
                    val res = downloadRemoteIoc(ip.url)
                    if (res != null) {
                        succeeded++
                        LogUtils.d(TAG, "update() downloaded -> $res")
                    } else {
                        LogUtils.w(TAG, "update() failed -> ${ip.url}")
                    }
                }   
            }
        }
        if (!loadedAnySource) {
            LogUtils.w(TAG, "update() no index could be loaded from any source")
            return
        }
        if (attempted == 0) {
            LogUtils.i(TAG, "No updates available; skipping downloads")
        }
        if (succeeded > 0) {
            setLatestUpdate()
        } else if (attempted > 0) {
            LogUtils.w(TAG, "No files succeeded; not updating latest_indicators_update")
        }
        LogUtils.d(TAG, "update() done: attempted=$attempted succeeded=$succeeded")
    }

    private data class IndicatorPlan(val url: String, val changed: Boolean)

    /*
     * This function determines if we need to download a given indicator.
     * This tries to prevent excessive network requests for indicators that haven't changed.
     * 
     */
    private fun buildDownloadPlan(
        item: SourceItem,
        latestUpdate: Long,
    ): List<IndicatorPlan> {
        return when (item) {
            is GitHubSourceItem -> {
                val url = item.url
                if (url.isBlank()) {
                    LogUtils.w(TAG, "buildDownloadPlan: skipped item with empty url")
                    emptyList()
                } else {
                    // fetch the latest commit epoch for the given GitHub source item
                    // if it's greater than the latest update, we need to fetch the new indicators
                    val changed = githubLatestCommitEpoch(item.owner, item.repo, item.branch, item.path) > latestUpdate
                    LogUtils.d(TAG, "plan: ${if (changed) "FETCH" else "SKIP"} $url")
                    listOf(IndicatorPlan(url, changed))
                }
            }
            is URLSourceItem -> {
                val url = item.url
                if (url.isBlank()) {
                    LogUtils.w(TAG, "buildDownloadPlan: skipped item with empty url")
                    emptyList()
                } else {
                    val isFileUrl = url.startsWith("file://")
                    val firstRun = latestUpdate == 0L
                    val destMissing = if (isFileUrl) {
                        val fileName = url.replaceFirst("^https?://".toRegex(), "").replace(Regex("[/\\\\]"), "_")
                        val dest = indicatorsFolder.resolve(fileName)
                        !Files.exists(dest)
                    } else {
                        false
                    }
                    val changed = when {
                        isFileUrl && (firstRun || destMissing) -> true
                        firstRun -> true
                        else -> false
                    }
                    LogUtils.d(TAG, "plan: ${if (changed) "FETCH" else "SKIP"} $url")
                    listOf(IndicatorPlan(url, changed))
                }
            }
        }
    }

}
