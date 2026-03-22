package org.osservatorionessuno.libmvt.common;

import org.osservatorionessuno.libmvt.common.logging.LogUtils;

import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;

public class IndicatorsUpdates {
    private static final String DEFAULT_GITHUB_RAW = "https://raw.githubusercontent.com/%s/%s/%s/%s";
    public static final Path MVT_DATA_FOLDER = Paths.get(System.getProperty("user.home"), ".mvt");

    private static final String TAG = "IndicatorsUpdates";

    private final Path latestUpdatePath;
    private final Path latestCheckPath;
    private final Path indicatorsFolder;

    private final String indexUrl;       // may be null -> default GitHub indicators.yaml
    private final String githubRawUrl;   // format string

    public IndicatorsUpdates() { this(null, null); }

    public IndicatorsUpdates(Path dataFolder, String indexUrl) {
        Path base = (dataFolder == null) ? MVT_DATA_FOLDER : dataFolder;
        this.indexUrl = indexUrl;
        this.githubRawUrl = DEFAULT_GITHUB_RAW;
        this.latestUpdatePath = base.resolve("latest_indicators_update");
        this.latestCheckPath  = base.resolve("latest_indicators_check");
        this.indicatorsFolder = base.resolve("iocs");

        try { Files.createDirectories(base); } catch (IOException ignored) {}
        try { Files.createDirectories(indicatorsFolder); } catch (IOException ignored) {}
        LogUtils.i(TAG, "Init with base=" + base + ", indicatorsFolder=" + indicatorsFolder + ", indexUrl=" + (indexUrl == null ? "(default GitHub)" : indexUrl));
    }

    /** Return the folder where indicators are stored. */
    public Path getIndicatorsFolder() { return indicatorsFolder; }

    // --------------------- Networking & IO helpers ---------------------

    private static String httpGetString(String url, int timeoutMs) throws IOException {
        return httpGetStringWithHeaders(url, timeoutMs, null);
    }

    private static String httpGetStringWithHeaders(String url, int timeoutMs, Map<String,String> headers) throws IOException {
        LogUtils.d(TAG, "HTTP GET (string) url=" + url + " timeoutMs=" + timeoutMs);
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setConnectTimeout(timeoutMs);
        conn.setReadTimeout(timeoutMs);
        conn.setInstanceFollowRedirects(true);
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Accept", "*/*");
        // GitHub API requires a UA
        conn.setRequestProperty("User-Agent", "bugbane/1.0 (+https://example.invalid)");
        if (headers != null) {
            for (Map.Entry<String,String> e : headers.entrySet()) {
                conn.setRequestProperty(e.getKey(), e.getValue());
            }
        }
        int code = conn.getResponseCode();
        long clen = -1;
        try { clen = conn.getContentLengthLong(); } catch (Throwable ignored) {}
        LogUtils.d(TAG, "Response code=" + code + " contentLength=" + clen);

        if (code != HttpURLConnection.HTTP_OK) {
            try (InputStream err = conn.getErrorStream()) {
                if (err != null) {
                    try (BufferedReader br = new BufferedReader(new InputStreamReader(err, StandardCharsets.UTF_8))) {
                        StringBuilder esb = new StringBuilder();
                        char[] buf = new char[2048];
                        int n; while ((n = br.read(buf)) >= 0) esb.append(buf, 0, n);
                        LogUtils.w(TAG, "Error body: " + esb);
                    }
                }
            } finally { conn.disconnect(); }
            return null;
        }

        StringBuilder sb = new StringBuilder();
        try (InputStream in = new BufferedInputStream(conn.getInputStream());
             InputStreamReader isr = new InputStreamReader(in, StandardCharsets.UTF_8);
             BufferedReader br = new BufferedReader(isr)) {
            char[] buf = new char[8192];
            int n, total = 0;
            while ((n = br.read(buf)) >= 0) { sb.append(buf, 0, n); total += n; }
            LogUtils.d(TAG, "Downloaded text chars=" + total);
        } finally { conn.disconnect(); }
        return sb.toString();
    }

    private static boolean httpGetToFile(String url, Path dest, int timeoutMs) throws IOException {
        LogUtils.d(TAG, "HTTP GET (file) url=" + url + " -> " + dest + " timeoutMs=" + timeoutMs);
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setConnectTimeout(timeoutMs);
        conn.setReadTimeout(timeoutMs);
        conn.setInstanceFollowRedirects(true);
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Accept", "*/*");
        conn.setRequestProperty("User-Agent", "bugbane/1.0 (+https://example.invalid)");
        int code = conn.getResponseCode();
        long clen = -1;
        try { clen = conn.getContentLengthLong(); } catch (Throwable ignored) {}
        LogUtils.d(TAG, "Response code=" + code + " contentLength=" + clen);

        if (code != HttpURLConnection.HTTP_OK) {
            try (InputStream err = conn.getErrorStream()) {
                if (err != null) {
                    try (BufferedReader br = new BufferedReader(new InputStreamReader(err, StandardCharsets.UTF_8))) {
                        StringBuilder esb = new StringBuilder();
                        char[] buf = new char[2048];
                        int n; while ((n = br.read(buf)) >= 0) esb.append(buf, 0, n);
                        LogUtils.w(TAG, "Error body: " + esb);
                    }
                }
            } finally { conn.disconnect(); }
            return false;
        }

        Files.createDirectories(dest.getParent());
        long totalBytes = 0;
        try (InputStream in = new BufferedInputStream(conn.getInputStream());
             BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(dest.toFile()))) {
            byte[] buf = new byte[32 * 1024];
            int n; while ((n = in.read(buf)) >= 0) { out.write(buf, 0, n); totalBytes += n; }
            LogUtils.d(TAG, "Saved file bytes=" + totalBytes + " to " + dest);
        } finally { conn.disconnect(); }
        return true;
    }

    private static String readSmallFile(Path p) throws IOException {
        try (BufferedReader br = Files.newBufferedReader(p, StandardCharsets.UTF_8)) {
            StringBuilder sb = new StringBuilder();
            char[] buf = new char[4096];
            int n; while ((n = br.read(buf)) >= 0) sb.append(buf, 0, n);
            return sb.toString();
        }
    }

    private static void writeSmallFile(Path p, String s) throws IOException {
        Files.createDirectories(p.getParent());
        try (BufferedWriter bw = Files.newBufferedWriter(p, StandardCharsets.UTF_8)) { bw.write(s); }
    }

    // --------------------- YAML index loading ---------------------

    @SuppressWarnings("unchecked")
    private Map<String, Object> getRemoteIndex() throws IOException {
        final String url = (indexUrl != null)
                ? indexUrl
                : String.format(githubRawUrl, "mvt-project", "mvt-indicators", "main", "indicators.yaml");

        LogUtils.d(TAG, "Fetching index url=" + url);
        String text;
        if (url.startsWith("file://")) {
            Path p = Paths.get(URI.create(url));
            LogUtils.d(TAG, "Reading local index from " + p);
            text = readSmallFile(p);
        } else {
            text = httpGetString(url, 15000);
            if (text == null) { LogUtils.w(TAG, "Index fetch returned null"); return null; }
        }

        final String trimmed = text.trim();
        LogUtils.d(TAG, "Index length=" + trimmed.length());
        LogUtils.d(TAG, "Parsing YAML index");

        try {
            LoaderOptions opts = new LoaderOptions();
            opts.setMaxAliasesForCollections(50);
            opts.setAllowDuplicateKeys(false);
            Yaml yaml = new Yaml(new SafeConstructor(opts));
            Object loaded = yaml.load(text);

            if (!(loaded instanceof Map)) {
                LogUtils.w(TAG, "YAML root is not a map; got=" + (loaded == null ? "null" : loaded.getClass().getName()));
                return null;
            }
            Map<String, Object> root = (Map<String, Object>) loaded;

            try {
                Object inds = root.get("indicators");
                int size = (inds instanceof List) ? ((List<?>) inds).size() : -1;
                LogUtils.d(TAG, "YAML parsed successfully; indicators.size=" + size);
            } catch (Throwable ignored) {}

            return root;
        } catch (Throwable t) {
            LogUtils.e(TAG, "SnakeYAML parse failed", t);
            return null;
        }
    }

    // --------------------- “Same logic as mvt” freshness checks ---------------------

    private static class GhRef {
        String owner, repo, branch, path;
        GhRef(String o, String r, String b, String p) { owner=o; repo=r; branch=b; path=p; }
        boolean isComplete() { return notBlank(owner) && notBlank(repo) && notBlank(path) && notBlank(branch); }
    }

    private static boolean notBlank(String s) { return s != null && !s.trim().isEmpty(); }

    /** If indexUrl is the default or a raw.githubusercontent.com URL, resolve owner/repo/branch/path. */
    private GhRef resolveIndexGhRef() {
        if (indexUrl == null) {
            return new GhRef("mvt-project", "mvt-indicators", "main", "indicators.yaml");
        }
        if (indexUrl.startsWith("https://raw.githubusercontent.com/")) {
            try {
                URI u = URI.create(indexUrl);
                // path like: /{owner}/{repo}/{branch}/{path...}
                String[] seg = u.getPath().split("/", 5);
                if (seg.length >= 5) {
                    return new GhRef(seg[1], seg[2], seg[3], seg[4]);
                }
            } catch (Throwable t) {
                LogUtils.w(TAG, "resolveIndexGhRef failed for " + indexUrl + ": " + t);
            }
        }
        return null; // not a GH raw URL; we can't commit-check it
    }

    /** Ask GitHub commits API for latest commit date (epoch seconds) for a file path. */
    private long githubLatestCommitEpoch(String owner, String repo, String branch, String path) {
        long t = githubLatestCommitEpochOnce(owner, repo, branch, path);
        if (t > 0) return t;

        // Fallbacks for repos that changed default branch or mis-specified branch in YAML
        if (!"main".equals(branch)) {
            LogUtils.d(TAG, "githubLatestCommitEpoch: retrying with branch=main");
            t = githubLatestCommitEpochOnce(owner, repo, "main", path);
            if (t > 0) return t;
        }
        if (!"master".equals(branch)) {
            LogUtils.d(TAG, "githubLatestCommitEpoch: retrying with branch=master");
            t = githubLatestCommitEpochOnce(owner, repo, "master", path);
            if (t > 0) return t;
        }
        return 0L;
    }

    private long githubLatestCommitEpochOnce(String owner, String repo, String branch, String path) {
        try {
            String url = "https://api.github.com/repos/"
                    + urlEnc(owner) + "/" + urlEnc(repo)
                    + "/commits?path=" + urlEnc(path)
                    + "&sha=" + urlEnc(branch)
                    + "&per_page=1";

            Map<String,String> headers = new java.util.HashMap<>();
            headers.put("Accept", "application/vnd.github+json");
            headers.put("User-Agent", "bugbane/1.0 (+https://example.invalid)");
            // If you have a token, uncomment the next line to avoid rate limits:
            // headers.put("Authorization", "Bearer " + yourToken);

            String body = httpGetStringWithHeaders(url, 15000, headers);
            if (body == null || body.isEmpty()) {
                LogUtils.w(TAG, "githubLatestCommitEpochOnce: null/empty response for " + owner + "/" + repo + "@" + branch + " path=" + path);
                return 0L;
            }

            String iso = extractFirstIsoDateFromCommits(body);
            if (iso == null || iso.isEmpty()) {
                LogUtils.w(TAG, "githubLatestCommitEpochOnce: no date found in response (commits empty?)");
                return 0L;
            }
            long epoch = java.time.Instant.parse(iso).getEpochSecond();
            LogUtils.d(TAG, "githubLatestCommitEpochOnce: " + owner + "/" + repo + "@" + branch + " path=" + path
                    + " -> " + iso + " (" + epoch + ")");
            return epoch;
        } catch (Exception e) {
            LogUtils.w(TAG, "githubLatestCommitEpochOnce failed: " + e);
            return 0L;
        }
    }

    /** Robustly extract commit.author.date from GitHub commits JSON (first item). */
    private static String extractFirstIsoDateFromCommits(String json) {
        try {
            Object parsed = new JSONTokener(json).nextValue();
            if (parsed instanceof JSONArray) {
                JSONArray arr = (JSONArray) parsed;
                if (arr.length() == 0) return null;
                JSONObject first = arr.getJSONObject(0);
                JSONObject commit = first.optJSONObject("commit");
                if (commit == null) return null;
                JSONObject author = commit.optJSONObject("author");
                if (author == null) return null;
                return author.optString("date", null); // ISO 8601, e.g., 2024-12-31T09:41:22Z
            } else if (parsed instanceof JSONObject) {
                // Often an error/rate-limit object: {"message": "...", "status": "...", ...}
                JSONObject obj = (JSONObject) parsed;
                String msg = obj.optString("message", "");
                if (!msg.isEmpty()) LogUtils.w(TAG, "GitHub API message: " + msg);
                return null;
            } else {
                return null;
            }
        } catch (Exception e) {
            // Keep logging terse to avoid spam; you already log callers.
            return null;
        }
    }


    private static String urlEnc(String s) {
        try { return URLEncoder.encode(s, "UTF-8"); } catch (Exception e) { return s; }
    }

    /** Returns true if commits indicate something newer than latestUpdate exists. */
    @SuppressWarnings("unchecked")
    private boolean isUpdateAvailable(Map<String,Object> index, long latestUpdate) {
        // 1) Check the index file itself (if we can resolve it on GitHub)
        GhRef idx = resolveIndexGhRef();
        if (idx != null && idx.isComplete()) {
            long t = githubLatestCommitEpoch(idx.owner, idx.repo, idx.branch, idx.path);
            if (t > latestUpdate) {
                LogUtils.d(TAG, "Index newer than latestUpdate (" + t + " > " + latestUpdate + ")");
                return true;
            }
        } else {
            LogUtils.d(TAG, "Index is not a GitHub raw URL; skipping index commit check");
        }

        // 2) If index didn't change, check each indicator github entry
        Object indicators = index.get("indicators");
        if (!(indicators instanceof Iterable<?>)) {
            LogUtils.w(TAG, "isUpdateAvailable: 'indicators' not iterable");
            return false;
        }
        for (Object obj : (Iterable<?>) indicators) {
            if (!(obj instanceof Map)) continue;
            Map<String, Object> map = (Map<String, Object>) obj;

            String type = stringOrEmpty(map.get("type"));
            if (!"github".equals(type)) continue;

            Object ghObj = map.get("github");
            if (!(ghObj instanceof Map)) continue;
            Map<String,Object> gh = (Map<String,Object>) ghObj;

            String owner  = stringOrEmpty(gh.get("owner"));
            String repo   = stringOrEmpty(gh.get("repo"));
            String branch = stringOrEmptyDefault(gh.get("branch"), "main");
            String path   = stringOrEmpty(gh.get("path"));
            if (owner.isEmpty() || repo.isEmpty() || path.isEmpty()) continue;

            long t = githubLatestCommitEpoch(owner, repo, branch, path);
            if (t > latestUpdate) {
                LogUtils.d(TAG, "Indicator newer than latestUpdate (" + t + " > " + latestUpdate + ") for " + owner + "/" + repo + "@" + branch + " path=" + path);
                return true;
            }
        }
        LogUtils.d(TAG, "No remote updates detected vs latestUpdate=" + latestUpdate);
        return false;
    }

    // --------------------- Downloads ---------------------

    private String downloadRemoteIoc(String url) throws IOException {
        Files.createDirectories(indicatorsFolder);
        String fileName = url.replaceFirst("^https?://", "").replaceAll("[/\\\\]", "_");
        Path dest = indicatorsFolder.resolve(fileName);
        LogUtils.d(TAG, "Downloading IOC url=" + url + " -> " + dest);

        if (url.startsWith("file://")) {
            Path p = Paths.get(URI.create(url));
            Files.copy(p, dest, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            LogUtils.d(TAG, "Copied local IOC " + p + " -> " + dest);
            return dest.toString();
        }

        boolean ok = httpGetToFile(url, dest, 15000);
        if (!ok) { LogUtils.w(TAG, "Failed to download IOC: " + url); return null; }
        return dest.toString();
    }

    // --------------------- Timestamps ---------------------

    public long getLatestCheck() {
        try {
            long v = Long.parseLong(readSmallFile(latestCheckPath).trim());
            LogUtils.d(TAG, "getLatestCheck=" + v + " (" + latestCheckPath + ")");
            return v;
        } catch (IOException | NumberFormatException e) {
            LogUtils.w(TAG, "getLatestCheck missing or invalid (" + latestCheckPath + ")");
            return 0;
        }
    }

    private void setLatestCheck() {
        try { long now = Instant.now().getEpochSecond(); writeSmallFile(latestCheckPath, Long.toString(now)); LogUtils.d(TAG, "setLatestCheck=" + now + " (" + latestCheckPath + ")"); }
        catch (IOException ignored) { LogUtils.w(TAG, "setLatestCheck failed"); }
    }

    public long getLatestUpdate() {
        try {
            long v = Long.parseLong(readSmallFile(latestUpdatePath).trim());
            LogUtils.d(TAG, "getLatestUpdate=" + v + " (" + latestUpdatePath + ")");
            return v;
        } catch (IOException | NumberFormatException e) {
            LogUtils.w(TAG, "getLatestUpdate missing or invalid (" + latestUpdatePath + ")");
            return 0;
        }
    }

    private void setLatestUpdate() {
        try { long now = Instant.now().getEpochSecond(); writeSmallFile(latestUpdatePath, Long.toString(now)); LogUtils.d(TAG, "setLatestUpdate=" + now + " (" + latestUpdatePath + ")"); }
        catch (IOException ignored) { LogUtils.w(TAG, "setLatestUpdate failed"); }
    }

    // --------------------- Public API ---------------------

    public Path download(String url) throws IOException {
        LogUtils.d(TAG, "download() called with url=" + url);
        String dl = downloadRemoteIoc(url);
        Path p = (dl != null) ? Paths.get(dl) : null;
        LogUtils.d(TAG, "download() result=" + p);
        return p;
    }

    @SuppressWarnings("unchecked")
    public void update() throws IOException {
        LogUtils.d(TAG, "update() start");
        setLatestCheck();

        Map<String, Object> index = getRemoteIndex();
        if (index == null) { LogUtils.w(TAG, "update() no index"); return; }

        long latestUpdate = getLatestUpdate();

        // Build per-item plan using commit times (index + each GH indicator)
        java.util.List<IndicatorPlan> plan = buildDownloadPlan(index, latestUpdate);

        // Decide if anything changed at all
        boolean anythingChanged = false;
        for (IndicatorPlan ip : plan) {
            if (ip.changed) { anythingChanged = true; break; }
        }
        if (!anythingChanged) {
            LogUtils.i(TAG, "No updates available; skipping downloads");
            return;
        }

        // Selective download: only changed items
        int attempted = 0, succeeded = 0;
        for (IndicatorPlan ip : plan) {
            if (!ip.changed) continue;
            attempted++;
            String res = downloadRemoteIoc(ip.url);
            if (res != null) { succeeded++; LogUtils.d(TAG, "update() downloaded -> " + res); }
            else { LogUtils.w(TAG, "update() failed -> " + ip.url); }
        }

        if (succeeded > 0) {
            setLatestUpdate();
        } else {
            LogUtils.w(TAG, "No files succeeded; not updating latest_indicators_update");
        }
        LogUtils.d(TAG, "update() done: attempted=" + attempted + " succeeded=" + succeeded);
    }


    public long countIndicators() {
        try (java.util.stream.Stream<Path> stream = Files.list(indicatorsFolder)) {
            long c = stream.count();
            LogUtils.d(TAG, "countIndicators folder=" + indicatorsFolder + " count=" + c);
            return c;
        } catch (IOException e) {
            LogUtils.e(TAG, "countIndicators failed for " + indicatorsFolder, e);
            return 0;
        }
    }

    // --------------------- utils ---------------------

    private static String stringOrEmpty(Object o) { return (o == null) ? "" : o.toString(); }
    private static String stringOrEmptyDefault(Object o, String dflt) {
        String s = stringOrEmpty(o);
        return s.isEmpty() ? dflt : s;
    }
    private static class IndicatorPlan {
        final String url;
        final boolean changed;
        final String reason;
        IndicatorPlan(String url, boolean changed, String reason) {
            this.url = url;
            this.changed = changed;
            this.reason = reason;
        }
    }

    // Build the download plan: which indicators should be fetched now?
    @SuppressWarnings("unchecked")
    private java.util.List<IndicatorPlan> buildDownloadPlan(Map<String,Object> index, long latestUpdate) {
        java.util.List<IndicatorPlan> plan = new java.util.ArrayList<>();

        // 1) Find index commit time (if resolvable on GitHub)
        long indexEpoch = 0L;
        GhRef idx = resolveIndexGhRef();
        if (idx != null && idx.isComplete()) {
            indexEpoch = githubLatestCommitEpoch(idx.owner, idx.repo, idx.branch, idx.path);
            if (indexEpoch > 0) {
                LogUtils.d(TAG, "Index latest epoch=" + indexEpoch + " (latestUpdate=" + latestUpdate + ")");
            } else {
                LogUtils.w(TAG, "Could not resolve latest commit epoch for index; treating non-GitHub items conservatively.");
            }
        } else {
            LogUtils.d(TAG, "Index not a GitHub raw URL; skipping index commit check");
        }

        // 2) Iterate indicators and decide per-item freshness
        Object indicators = index.get("indicators");
        if (!(indicators instanceof Iterable<?>)) {
            LogUtils.w(TAG, "buildDownloadPlan: 'indicators' not iterable");
            return plan;
        }

        for (Object obj : (Iterable<?>) indicators) {
            if (!(obj instanceof Map)) continue;
            Map<String,Object> item = (Map<String,Object>) obj;

            String url = indicatorDownloadUrl(item);
            if (url == null || url.trim().isEmpty()) {
                LogUtils.w(TAG, "buildDownloadPlan: skipped item with empty url");
                continue;
            }

            String type = stringOrEmpty(item.get("type"));
            boolean changed = false;
            String reason = "";

            if ("github".equals(type)) {
                Object ghObj = item.get("github");
                if (ghObj instanceof Map) {
                    Map<String,Object> gh = (Map<String,Object>) ghObj;
                    String owner  = stringOrEmpty(gh.get("owner"));
                    String repo   = stringOrEmpty(gh.get("repo"));
                    String branch = stringOrEmptyDefault(gh.get("branch"), "main");
                    String path   = stringOrEmpty(gh.get("path"));

                    if (!owner.isEmpty() && !repo.isEmpty() && !path.isEmpty()) {
                        long t = githubLatestCommitEpoch(owner, repo, branch, path);
                        if (t > latestUpdate) {
                            changed = true;
                            reason = "github(" + owner + "/" + repo + "@" + branch + ":" + path + ") t=" + t + " > " + latestUpdate;
                        } else {
                            reason = "github unchanged (t <= latestUpdate)";
                        }
                    } else {
                        // malformed GH entry: when in doubt, only refresh if the index changed
                        changed = (indexEpoch > latestUpdate && indexEpoch > 0);
                        reason = "github incomplete fields; fallback to index comparison";
                    }
                } else {
                    // no github block: fallback to index
                    changed = (indexEpoch > latestUpdate && indexEpoch > 0);
                    reason = "missing github block; fallback to index comparison";
                }
            } else {
                // Non-GitHub item.
                boolean isFileUrl = url.startsWith("file://");
                boolean firstRun  = (latestUpdate == 0);

                // If it's a local file, refresh at least once — or when the dest is missing.
                boolean destMissing = false;
                if (isFileUrl) {
                    String fileName = url.replaceFirst("^https?://", "").replaceAll("[/\\\\]", "_");
                    Path dest = indicatorsFolder.resolve(fileName);
                    try {
                        destMissing = !java.nio.file.Files.exists(dest);
                    } catch (Throwable ignored) {}
                }

                if (isFileUrl && (firstRun || destMissing)) {
                    changed = true;
                    reason  = "local file; " + (firstRun ? "first run" : "destination missing");
                } else if (firstRun) {
                    // For any other non-GitHub item, refresh on first run.
                    changed = true;
                    reason  = "non-github; first run";
                } else {
                    // Otherwise follow index commits (which we can’t query here).
                    changed = (indexEpoch > latestUpdate && indexEpoch > 0);
                    reason  = "non-github; follow index (indexEpoch=" + indexEpoch + ")";
                }            }

            LogUtils.d(TAG, "plan: " + (changed ? "FETCH  " : "SKIP   ") + url + "  -- " + reason);
            plan.add(new IndicatorPlan(url, changed, reason));
        }

        return plan;
    }

    // Build download URL for an item (github->raw, else download_url)
    @SuppressWarnings("unchecked")
    private String indicatorDownloadUrl(Map<String,Object> item) {
        String type = stringOrEmpty(item.get("type"));
        if ("github".equals(type)) {
            Object ghObj = item.get("github");
            if (!(ghObj instanceof Map)) return "";
            Map<String,Object> gh = (Map<String,Object>) ghObj;
            String owner  = stringOrEmpty(gh.get("owner"));
            String repo   = stringOrEmpty(gh.get("repo"));
            String branch = stringOrEmptyDefault(gh.get("branch"), "main");
            String path   = stringOrEmpty(gh.get("path"));
            if (owner.isEmpty() || repo.isEmpty() || path.isEmpty()) return "";
            return String.format(githubRawUrl, owner, repo, branch, path);
        }
        return stringOrEmpty(item.get("download_url"));
    }
}
