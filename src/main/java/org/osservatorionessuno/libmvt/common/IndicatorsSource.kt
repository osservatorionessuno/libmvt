package org.osservatorionessuno.libmvt.common

import org.osservatorionessuno.libmvt.common.logging.LogUtils
import java.net.URI
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Paths
import org.yaml.snakeyaml.LoaderOptions
import org.yaml.snakeyaml.Yaml
import org.yaml.snakeyaml.constructor.SafeConstructor

internal const val DEFAULT_GITHUB_RAW = "https://raw.githubusercontent.com/%s/%s/%s/%s"

/*
 * Sources are YAML files that contain a list of indicators indexes.
 * Sources can be local (file://) or remote (https://).

 * The format of the YAML file is:
 *
 * indicators:
 *   - name: <indicator name>
 *     type: <indicator type> (github, url)
 *     url: <indicator URL>
 *     github:
 *       owner: <github owner>
 *       repo: <github repo>
 *       branch: <github branch>
 *       path: <github path>
 *
 * The type "github" is used to indicate that the indicator is a GitHub raw URL.
 * The type "url" is used to indicate that the indicator is a URL.
 *
 */

/*
 * A SourceItem is a single IoC URL in a STIX2 format.
 */
sealed class SourceItem

data class GitHubSourceItem(
    val owner: String,
    val repo: String,
    val branch: String,
    val path: String,
) : SourceItem() {
    val url: String
        get() = String.format(DEFAULT_GITHUB_RAW, owner, repo, branch, path)
}

data class URLSourceItem(
    val url: String,
) : SourceItem()

data class IndicatorsSource(
    val url: String,
) : List<SourceItem> by loadSourceItems(url)

/*
 * Load a source from the given URL and parses all indicators URLs. 
 */
private fun loadSourceItems(url: String): List<SourceItem> {
    val content = retrieveSourceContent(url)
    if (content == null) {
        throw IllegalArgumentException("Failed to load from source: $url")
    }
    val parsed = parseSourceYAML(content)
    if (parsed == null) {
        throw IllegalArgumentException("Failed to parse source: $url")
    }

    val items = mutableListOf<SourceItem>()
    for (raw in parsed["indicators"] as? Iterable<*> ?: emptyList<Any>()) {
        @Suppress("UNCHECKED_CAST")
        val indicator = raw as Map<String, Any>
        when (indicator["type"]) {
            "github" -> {
                val ghObj = indicator["github"]
                if (ghObj !is Map<*, *>) {
                    throw IllegalArgumentException("Invalid github field for indicator: ${indicator["name"]}")
                }
                @Suppress("UNCHECKED_CAST")
                val github = ghObj as Map<String, Any>
                val owner = stringOrEmpty(github["owner"])
                val repo = stringOrEmpty(github["repo"])
                val branch = stringOrEmptyDefault(github["branch"], "main")
                val path = stringOrEmpty(github["path"])
                items.add(GitHubSourceItem(owner, repo, branch, path))
            }
            "url", "download" -> {
                items.add(URLSourceItem(stringOrEmpty(indicator["url"])))
            }
            else -> {
                throw IllegalArgumentException("Invalid indicator type: ${indicator["type"]}")
            }
        }
    }
    return items
}

private fun stringOrEmpty(o: Any?): String = o?.toString() ?: ""
private fun stringOrEmptyDefault(o: Any?, dflt: String): String {
    val s = stringOrEmpty(o)
    return if (s.isEmpty()) dflt else s
}

/*
 * Retrieve the content of a source from the given URL.
 * URLs can be local (file://) or remote (https://).
 */
private fun retrieveSourceContent(url: String): String? {
    return try {
        if (url.startsWith("file://")) {
            val p = Paths.get(URI.create(url))
            Files.readString(p, StandardCharsets.UTF_8)
        } else {
            NetworkUtils.httpGetString(url, 15_000) ?: run {
                return null
            }
        }
    } catch (e: Exception) {
        LogUtils.e("IndicatorsSource", "Failed to load from source: $url", e)
        return null
    }
}

/*
 * Parse the content of a source from the given YAML text.
 */
private fun parseSourceYAML(text: String): Map<String, Any>? {
    return try {
        val opts = LoaderOptions().apply {
            maxAliasesForCollections = 50
            isAllowDuplicateKeys = false
        }
        val loaded: Any? = Yaml(SafeConstructor(opts)).load(text)
        if (loaded !is Map<*, *>) return null

        @Suppress("UNCHECKED_CAST")
        loaded as Map<String, Any>
    } catch (t: Throwable) {
        LogUtils.e("IndicatorsSource", "Failed to parse YAML: $text", t)
        return null
    }
}
