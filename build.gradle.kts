plugins {
    kotlin("jvm") version "2.0.0"
    application
}

group = "org.osservatorionessuno"
version = "0.0.1"

val generatedSourcesDir = layout.buildDirectory.dir("generated/sources/buildInfo/kotlin")

repositories {
    mavenCentral()
    google()
    maven("https://jitpack.io")
}

dependencies {
    // https://github.com/rednaga/axmlprinter — JitPack: v1.0.0 ok; v2.0.0 tag currently fails to build there
    implementation("com.github.rednaga:axmlprinter:v1.0.0")
    // https://android.googlesource.com/platform/tools/apksig/ (published as com.android.tools.build:apksig)
    implementation("com.android.tools.build:apksig:8.13.2")
    implementation("org.json:json:20240303")
    implementation("org.ahocorasick:ahocorasick:0.6.3")
    implementation("org.yaml:snakeyaml:2.2")
    implementation("org.jetbrains.kotlinx:kotlinx-cli:0.3.6")
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
}

application {
    mainClass.set("org.osservatorionessuno.Main")
}

tasks.register("generateBuildInfo") {
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
        kotlin.srcDir(generatedSourcesDir)
    }
}

tasks.compileKotlin {
    dependsOn("generateBuildInfo")
}

java {
    withSourcesJar()
    withJavadocJar()
}

tasks.named<Jar>("sourcesJar") {
    dependsOn("generateBuildInfo")
}

tasks.jar {
    manifest {
        attributes(
            "Implementation-Title" to name,
            "Implementation-Version" to version,
        )
    }
}

tasks.test {
    useJUnitPlatform()
}

