/*
 * Copyright (c) 2018-2019 Pavel Vasin
 * Copyright (c) 2018 Blacknet Team
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet

import com.rfksystems.blake2b.security.Blake2bProvider
import io.ktor.server.engine.commandLineEnvironment
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.util.error
import kotlinx.coroutines.debug.DebugProbes
import mu.KotlinLogging
import ninja.blacknet.core.Staker
import ninja.blacknet.db.*
import ninja.blacknet.network.Node
import java.io.File
import java.io.FileInputStream
import java.security.Security
import java.util.logging.LogManager

private val logger = KotlinLogging.logger {}

object Main {
    @JvmStatic
    fun main(args: Array<String>) {
        Security.addProvider(Blake2bProvider())

        Runtime
        Config

        val inStream = FileInputStream(File(Config.dir, "logging.properties"))
        LogManager.getLogManager().readConfiguration(inStream)
        inStream.close()

        logger.info("Starting ${Version.name} node")
        logger.info("CPU: ${Runtime.availableProcessors} cores ${System.getProperty("os.arch")}")
        logger.info("OS: ${System.getProperty("os.name")} ${System.getProperty("os.version")}")
        logger.info("VM: ${System.getProperty("java.vm.name")} ${System.getProperty("java.vm.version")}")

        if (!Runtime.windowsOS && System.getProperty("user.name") == "root")
            logger.warn("Running as root")

        if (Config.debugCoroutines) {
            logger.warn("Installing debug probes, node may work slower")
            try {
                DebugProbes.install()
            } catch (e: Throwable) {
                logger.error(e)
                Config.debugCoroutines = false
            }
        }

        if (Config.portable())
            logger.info("Portable mode")
        logger.info("Using data directory ${Config.dataDir.getAbsolutePath()}")

        LevelDB
        BlockDB
        WalletDB
        LedgerDB
        PeerDB
        Node
        Staker

        /* Launch Blacknet API web-server using Ktor.
         *
         * Blacknet API web-server logic is implemented in
         * ninja.blacknet.api.APIServer
         * ninja.blacknet.api.PublicServer
         *
         * Ktor is a framework for building asynchronous servers and clients
         * in connected systems using the powerful Kotlin programming language.
         * https://ktor.io/
         *
         * Ktor configuration is stored in
         * config/ktor.conf public server
         * config/rpc.conf private server
         * https://ktor.io/servers/engine.html
         *
         */
        if (Config.publicAPI())
            embeddedServer(Netty, commandLineEnvironment(arrayOf("-config=" + File(Config.dir, "ktor.conf")))).start(wait = false)
        if (Config.regTest)
            embeddedServer(Netty, commandLineEnvironment(arrayOf("-config=" + File(Config.dir, "regtest.conf")))).start(wait = true)
        else
            embeddedServer(Netty, commandLineEnvironment(arrayOf("-config=" + File(Config.dir, "rpc.conf")))).start(wait = true)
    }
}
