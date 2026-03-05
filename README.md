# libmvt

Kotlin/Java library to scan acquisitions following the [MVT](https://docs.mvt.re/en/latest/) framework approach.
The library is used by [Bugbane](https://github.com/osservatorionessuno/bugbane) but can also be used standalone.

Currently the library is in alpha phase and fast-moving development so:
- no Maven pre-compiled package is available
- no standalone package is available
- API interfaces are unstable and can change heavily between versions
- expect bugs

## Standalone (CLI)

Run analysis on an AndroidQF output directory or zip (same flow as Bugbane, without Android):

```bash
./gradlew run --args="[--indicators <dir>] <path-to-directory-or.zip>"

# Alternatively
./gradlew build
java -jar build/libs/libmvt-0.1.0-SNAPSHOT.jar [--indicators <dir>] <directory-or.zip>
```
