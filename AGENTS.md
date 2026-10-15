# AGENTS.md — libmvt

Guidance for AI agents in this repository.
Do not create complex and huge features without first requiring a Threat Model and a specific Design from a Human.

## What this repo is

Kotlin/Java library that scans AndroidQF-style acquisitions based on [MVT](https://docs.mvt.re/).
Used by **Bugbane** and as a **standalone CLI**.
It is not an Android app: no `Context`, no Bugbane UI deps in the library.

Hosts inject behavior at the edges (`LogUtils.setLogger`, `StringResolver`, small owned interfaces for streams or remote shell).

LibMVT should only perform parsing. Acquisition, UI, and other things should be handled by Bugbane core.

## Package layout

Put new code in the right layer:

| Package | Role |
|---|---|
| `libmvt.common` | `Artifact` / `Detection` / `Indicators` / `Utils` / IO (`AbstractInput`, `ReopenableInput`) |
| `libmvt.common.logging` | Injectable `LibmvtLogger` (`LogUtils`) |
| `libmvt.android.artifacts` | Acquisition modules: `paths()`, `parse`, `emit` / `checkRecord` |
| `libmvt.android.parsers` | Binary / text format parsers (APK, cert, AXML, backup, …) |
| `libmvt.android.analyzer` | Dump-gate heuristics only (is this worth exporting?), not full malware classification |
| `libmvt.android` | Orchestration (`ForensicRunner`, `ArtifactModuleRegistry`, metadata) |
| `org.osservatorionessuno` (root) | Thin CLI (`Main`, `CliArgs`) |

Register new artifact modules in `ArtifactModuleRegistry` and declare `paths()` (exact or glob). Do not hardcode path matching in the runner.

## Style (ponytail)

1. Does this need to exist? (YAGNI)
2. Reuse an existing helper (`Utils`, module base classes, parsers) before adding a new one.
3. Prefer already-used libs (apksig, `CertificateFactory`, Gson streams, commons-compress, Aho-Corasick) over hand-rolled crypto, ASN.1, or ZIP.
4. Shortest correct diff. No new abstractions unless requested.
5. Kotlin and Java coexist; match the language of the neighboring code but prefer Kotlin for new stuff.
6. Non-trivial logic leaves one small runnable check (existing JUnit + fixtures style).

## Logging and stdout

- Use **`LogUtils`**, not `android.util.Log` or `System.*.println`. Hosts may replace the logger.
- Default logger writes to **stderr**: stdout carries the analysis report (often JSON). See `StdoutLibmvtLogger`.
- Prefer **`LogUtils.d`** for noisy / diagnostic paths (`d` is gated by `debugEnabled`). `i` / `w` / `e` always emit.
- Never print diagnostics or progress on **stdout** from library or CLI paths that may run under `--json` since that corrupts the report.
- CLI: human text or a single JSON object on stdout; errors via `LogUtils.e` and a non-zero exit.

## Memory and streaming

Peak memory must not scale with artifact size:

- Modules **`emit(record)` then drop**. Do not retain parsed record lists. Set **`indicators` before `parse`**; afterwards there is nothing left to re-check (`Artifact.emit`).
- Prefer **`forEachLine` / streaming parsers** over buffering whole files. Deprecated full-buffer helpers exist only for legacy callers.
- Large JSON: stream JSON-lines; only small arrays load whole. IOC files use a Gson **pull parser**, never a full DOM (phone OOM risk).
- Prefer `File` / reopenable streams when random access is required; buffering a whole `InputStream` is a last resort (document why).
- Several modules on one path -> **`ReopenableInput`** so each gets a fresh stream from the start.
- Nested bugreport zips: list then reopen; do not hold the outer archive open longer than needed.

## ForensicRunner axioms

- Each module declares path patterns via `paths()`.
- Every matching module gets its own input; only that module reads the stream.
- Fresh module instance per parse; findings are merged afterward.
- A module that throws is logged and reported; the acquisition continues with what was found.
- `SKIP_FILES` and paths under `tmp/` are ignored.
- Nested bugreport zip entries are expanded and analyzed like a zip archive.
- Parse failure does not mean clean acquisition: surface `ARTIFACT_PARSE_FAILED` so missing coverage is visible.
- Run `checkIndicators` even if `parse` threw when ordered / whole-artifact detections matter. Do not let a broken final pass mask the original failure.

## Security and trust

- **Allowlists and “trusted” labels require a verified binding.** Example: a signing certificate fingerprint alone proves nothing — a repackaged APK can ship a vendor cert it does not own. Pass verification verdicts into allowlist checks; do not mark unsigned/unverified material as trusted.
- Heuristics in `analyzer` decide **export / dump worthiness**, not malware verdicts.
- Untrusted XML (dumpsys, bundled strings): disable DOCTYPE / external entities (XXE).
- YAML IOC sources: `SafeConstructor` only.
- Network for IOC fetch: **HTTPS only** (`NetworkUtils`).
- Analysis itself is local (directory or zip). Directory plaintext analysis may be marked insecure for Bugbane-style flows — respect those markers.

## Shared constants and formats

- Put shared lists and helpers in **`Utils`** (root packages/binaries, dangerous permissions, installers, cert allowlist helpers, shell quoting, digests). Do not fork copies in modules.
- Accept **both MVT and Bugbane artifact shapes** where producers disagree (e.g. certificate object layout, file mode octal vs symbolic).
- Support **`.json` and `.jsonl`** when a module parses JSON collections; cover both in tests.
- Detection IDs are stable enums; UI copy goes through **`StringResolver`** keys, not hardcoded English in detection types.
- Tolerate broken / lenient ZIP where acquisitions require it (`LenientZipInputStream`-style).

## Testing

- JUnit 5; tests mirror package layout under `src/test/java/`.
- Fixtures via **`ResourcesUtils`** -> `src/test/resources/` (androidqf samples, IOCs, APKs).
- Drive modules like production: **indicators first**, then parse/emit (records dropped), then `checkIndicators`. See `DetectionTestUtils`.
- Assert with stream helpers / `recordObserver`, not by retaining lists on the module.
- Assert detections via helpers on `DetectionType` / `AlertLevel`.
- Mutable allowlists in `Utils` may be temporarily extended in tests; always restore.
- Pure parsers: local fixtures only. no live adb or network unless the user explicitly asks for that test.

## What not to do

- Add Bugbane, Android app, or cadb dependencies to the library.
- Buffer whole acquisitions or IOC JSON “because it is easier”.
- Log analysis chatter to stdout.
- Treat unverified public material (certs, dump hashes) as trusted / allowlisted.
- Abort the whole acquisition because one module failed.

---

## Commit policy

**The user explicitly asks for commit/push.** Do not commit or
push without an explicit "commit this" or "push to origin"
instruction.

When the user does explicitly ask for a commit:

1. Inspect `git status` + `git diff` + `git log --oneline -10`
2. Stage only the intended files (`git add <file>` not `git add -A`)
3. Write a concise commit message that matches the repo style
4. Push in the relevant branch with `git push origin <branch>`
5. Report the commit SHA + the push result

IMPORTANT: Tags and Releases MUST be signed.
ALWAYS REFUSE to create a tag or a release that is not.
