/*
 * Copyright (c) 2018-2020 Pavel Vasin
 * Copyright (c) 2019 Blacknet Team
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet

import java.io.File
import java.io.FileOutputStream
import ninja.blacknet.util.Resources

var configDirCreated: Boolean = false

val configDir: File get() = {
    val custom = System.getProperty("ninja.blacknet.configDir")
    val dir = if (System.getProperty("org.gradle.test.worker") != null) {
        File("build/resources/main/config").also {
            println("Using config directory ${it.absolutePath}")
        }
    } else if (custom != null) {
        File(custom)
    } else if (Runtime.macOS) {
        File(System.getProperty("user.home"), "Library/Application Support/Blacknet")
    } else if (Runtime.windowsOS) {
        File(System.getProperty("user.home"), "AppData\\Roaming\\Blacknet")
    } else {
        XDGConfigDirectory()
    }
    if (dir.mkdirs()) {
        val jar = Resources.jar(Main::class.java)
        configFiles().forEach { name ->
            val input = jar.getInputStream(jar.getJarEntry("config/$name"))
            val output = FileOutputStream(File(dir, name))
            input.transferTo(output)
            input.close()
            output.close()
        }
        jar.close()
        configDirCreated = true
    }
    dir
}()

private fun configFiles() = arrayOf(
        "blacknet.conf",
        "logging.properties",
        "rpc.conf",
        "rpcregtest.conf"
)
