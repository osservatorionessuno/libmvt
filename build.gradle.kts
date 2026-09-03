plugins {
    alias(libs.plugins.kotlin.jvm)
    application
}

group = "org.osservatorionessuno"
version = "0.4.1"

val generatedSourcesDir = layout.buildDirectory.dir("generated/sources/buildInfo/kotlin")

repositories {
    mavenCentral()
    google()
    maven("https://jitpack.io")
}

dependencies {
    // https://github.com/rednaga/axmlprinter — JitPack: v1.0.0 ok; v2.0.0 tag currently fails to build there
    implementation(libs.axmlprinter)
    // https://android.googlesource.com/platform/tools/apksig/ (published as com.android.tools.build:apksig)
    implementation(libs.apksig)
    implementation(libs.org.json)
    implementation(libs.ahocorasick)
    implementation(libs.gson)
    implementation(libs.snakeyaml)
    implementation(libs.kotlinx.cli)
    implementation(libs.protobuf.javalite)
    implementation(libs.commons.compress)
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
}

application {
    mainClass.set("org.osservatorionessuno.Main")
}

val generateBuildInfo = tasks.register("generateBuildInfo") {
    outputs.dir(generatedSourcesDir)

    val outputDir = generatedSourcesDir.get().asFile

    doLast {
        val pkg = "org.osservatorionessuno"
        val pkgPath = pkg.replace('.', '/')
        val file = outputDir.resolve("$pkgPath/BuildInfo.kt")
        file.parentFile.mkdirs()
        file.writeText(
            """
            package $pkg

            object BuildInfo {
                const val NAME = "${project.name}"
                const val VERSION = "${project.version}"
            }
            """.trimIndent(),
        )
    }
}

kotlin {
    jvmToolchain(17)
    sourceSets.main {
        // Tell Gradle which task produces this directory to avoid implicit-dependency validation errors.
        kotlin.srcDir(
            files(generatedSourcesDir).builtBy(generateBuildInfo),
        )
    }
}

tasks.compileKotlin {
    dependsOn(generateBuildInfo)
}

java {
    withSourcesJar()
    withJavadocJar()
}

tasks.named<Jar>("sourcesJar") {
    dependsOn(generateBuildInfo)
}

tasks.jar {
    manifest {
        attributes(
            "Implementation-Title" to name,
            "Implementation-Version" to version,
        )
    }
}

tasks.withType<AbstractArchiveTask>().configureEach {
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        showStandardStreams = true
    }
}

