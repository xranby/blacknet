/*
 * Copyright (c) 2018-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

import nl.javadude.gradle.plugins.license.DownloadLicenses
import nl.javadude.gradle.plugins.license.LicenseMetadata
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile
import java.net.URI

allprojects {
    group = "ninja.blacknet"
    version = "0.3-SNAPSHOT"
}

buildscript {
    dependencies {
        classpath("org.jetbrains.kotlinx:atomicfu-gradle-plugin:0.14.4")
    }
}

plugins {
    kotlin("jvm") version Versions.kotlin
    kotlin("plugin.serialization") version Versions.kotlin
    application
    distribution
    id("com.github.hierynomus.license-report") version "0.15.0"
}

apply<kotlinx.atomicfu.plugin.gradle.AtomicFUGradlePlugin>()

repositories {
    jcenter()
}

dependencies {
    implementation(project(":blacknet-runtime"))
    implementation("org.jetbrains.kotlin:kotlin-stdlib-jdk8:${Versions.kotlin}")
    implementation("io.ktor:ktor-network:${Versions.ktor}")
    implementation("io.ktor:ktor-server-netty:${Versions.ktor}") {
        exclude("org.eclipse.jetty", "jetty-parent")
        exclude("org.eclipse.jetty.alpn", "alpn-api")
    }
    implementation("io.ktor:ktor-websockets:${Versions.ktor}")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:${Versions.coroutines}")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-debug:${Versions.coroutines}")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-jdk8:${Versions.coroutines}")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-core:${Versions.serialization}")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:${Versions.serialization}")
    implementation("org.apache.commons:commons-collections4:4.4")
    implementation("net.i2p.crypto:eddsa:0.3.0")
    implementation("com.rfksystems:blake2b:1.0.0")
    implementation("org.iq80.leveldb:leveldb:0.12")
    implementation("org.slf4j:slf4j-jdk14:1.7.30")
    implementation("io.github.microutils:kotlin-logging:1.7.9")
    implementation("com.google.guava:guava:29.0-jre")
    implementation("org.bitlet:weupnp:${Versions.weupnp}")
    implementation("org.bouncycastle:bcprov-jdk15on:${Versions.bouncycastle}")
    implementation(files("buildSrc/libs/leveldbjni-all-${Versions.leveldbjni}.jar"))
    testImplementation("org.jetbrains.kotlin:kotlin-test-testng:${Versions.kotlin}") {
        exclude("aopalliance", "aopalliance")
        exclude("junit", "junit")
    }
}

application {
    mainClassName = "ninja.blacknet.Main"
}

distributions {
    main {
        contents {
            from("LICENSE.txt")
            from("3RD-PARTY-LICENSES.txt")
        }
    }
}

val compileKotlin by tasks.existing(KotlinCompile::class) {
    kotlinOptions {
        jvmTarget = "1.8"
        freeCompilerArgs = listOf(
                "-Xjvm-default=all",
                "-Xuse-experimental=kotlin.ExperimentalUnsignedTypes"
        )
    }
}

val compileTestKotlin by tasks.existing(KotlinCompile::class) {
    kotlinOptions {
        jvmTarget = "1.8"
    }
}

val downloadLicenses by tasks.existing(DownloadLicenses::class) {
    doFirst {
        val konfigurations = configurations.toTypedArray()
        configurations.create("xonfigurations").extendsFrom(*konfigurations)
    }
    licenses = mapOf(
        "org.bitlet:weupnp:${Versions.weupnp}" to LicenseMetadata("GNU LESSER GENERAL PUBLIC LICENSE 2.1", "https://www.gnu.org/licenses/old-licenses/lgpl-2.1.en.html"),
        "org.bouncycastle:bcprov-jdk15on:${Versions.bouncycastle}" to LicenseMetadata("MIT License", "https://opensource.org/licenses/MIT")
    )
    dependencyConfiguration = "xonfigurations"
}

val jar by tasks.existing(Jar::class) {
    manifest {
        dirtyDescribeGit(buildDir.getParentFile())?.let { revision ->
            attributes("Build-Revision" to revision)
        }
        attributes(
                "Implementation-Title" to project.name.toString(),
                "Implementation-Vendor" to "Blacknet Team",
                "Implementation-Version" to project.version.toString()
        )
    }
}

val run by tasks.existing(JavaExec::class) {
    classpath = files(tasks.jar) + classpath.filter { !it.startsWith(buildDir) }
    systemProperties = defaultSystemProperties
}

val startScripts by tasks.existing(CreateStartScripts::class) {
    defaultJvmOpts = defaultSystemProperties.map { (key, value) -> "-D$key=$value" }
}

val test by tasks.existing(Test::class) {
    useTestNG()
}

val wrapper by tasks.existing(Wrapper::class) {
    gradleVersion = "6.8.2"
    distributionType = Wrapper.DistributionType.BIN
    distributionSha256Sum = "8de6efc274ab52332a9c820366dd5cf5fc9d35ec7078fd70c8ec6913431ee610"
}

val defaultSystemProperties: Map<String, Any> = mapOf(
    // Output hexadecimal values with lower case letters
    // "ninja.blacknet.codec.base.hex.lowercase" to true,
    // Indent JSON returned by RPC API
    // "ninja.blacknet.serialization.json.indented" to true,
    // Regression testing mode
    // "ninja.blacknet.regtest" to true,
)
