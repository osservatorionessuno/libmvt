plugins {
    kotlin("jvm") version "2.0.0"
    application
}

group = "com.example"
version = "0.1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

application {
    mainClass.set("com.example.HelloWorld")
}

kotlin {
    jvmToolchain(17)
}

java {
    withSourcesJar()
    withJavadocJar()
}

tasks.test {
    useJUnitPlatform()
}

