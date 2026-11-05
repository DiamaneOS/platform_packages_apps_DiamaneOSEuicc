// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

// The core sources and host tests as Android.bp builds them, plus the fuzz targets (Jazzer).
// Versions are pinned here and in gradle.lockfile, checksums in gradle/verification-metadata.xml.
plugins {
    kotlin("jvm") version "2.0.21"
}

dependencyLocking {
    lockAllConfigurations()
}

kotlin {
    jvmToolchain(21)
}

sourceSets {
    main {
        kotlin.srcDir("../../src/de/diamaneos/euicc/core")
    }
    test {
        kotlin.srcDir("../src")
    }
    create("fuzz") {
        kotlin.srcDir("src")
        compileClasspath += main.get().output + test.get().output
        runtimeClasspath += main.get().output + test.get().output
    }
}

val fuzzImplementation: Configuration by configurations.getting {
    extendsFrom(configurations.testImplementation.get())
}

dependencies {
    testImplementation("junit:junit:4.13.2")
    fuzzImplementation("com.code-intelligence:jazzer:0.30.0")
    fuzzImplementation("com.code-intelligence:jazzer-api:0.30.0")
}

// Android.bp packs res/raw/gsma_ci_*.pem as java_resources at res/raw.
tasks.processTestResources {
    from("../../res/raw") {
        include("gsma_ci_*.pem")
        into("res/raw")
    }
}

tasks.test {
    testLogging {
        events("failed")
        showStandardStreams = false
    }
}

// The fuzz classpath, for fuzz.sh.
tasks.register("fuzzClasspath") {
    val classpath = sourceSets["fuzz"].runtimeClasspath
    dependsOn("fuzzClasses")
    doLast {
        file("build/fuzz-classpath.txt").writeText(classpath.asPath)
    }
}
