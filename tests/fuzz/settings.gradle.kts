// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

// Host build for the core tests and the fuzz targets. Not part of the platform build.
pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositories {
        mavenCentral()
    }
}

rootProject.name = "diamaneos-euicc-host"
