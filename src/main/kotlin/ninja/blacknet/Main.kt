/*
 * Copyright (c) 2018-2020 Pavel Vasin
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
import java.io.File
import java.io.FileInputStream
import java.security.Security
import java.util.logging.LogManager
import kotlin.system.exitProcess
import kotlinx.coroutines.debug.DebugProbes
import mu.KotlinLogging
import ninja.blacknet.core.Staker
import ninja.blacknet.core.TxPool
import ninja.blacknet.db.*
import ninja.blacknet.network.ChainFetcher
import ninja.blacknet.network.Node
import org.bouncycastle.jce.provider.BouncyCastleProvider

private val logger = KotlinLogging.logger {}

object Main {
    @JvmStatic
    fun main(args: Array<String>) {
        if (System.getProperty("ninja.blacknet.createConfigAndExit") != null) {
            configDir
            exitProcess(status = if (configDirCreated) {
                println("Created configuration directory $configDir")
                0
            } else {
                println("Configuration directory already exists or cannot be created $configDir")
                1
            })
        }

        System.setProperty("java.util.logging.manager", "ninja.blacknet.logging.LogManager")
        FileInputStream(File(configDir, "logging.properties")).let { fileInputStream ->
            LogManager.getLogManager().readConfiguration(fileInputStream)
            fileInputStream.close()
        }

        Security.addProvider(Blake2bProvider())
        Security.addProvider(BouncyCastleProvider())

        Runtime.addShutdownHook {
            logger.debug { "Shutting down logger" }
            (LogManager.getLogManager() as ninja.blacknet.logging.LogManager).shutDown()
        }

        try {
            Config.instance
        } catch(e: ExceptionInInitializerError) {
            println("Error reading configuration file ${File(configDir, "blacknet.conf")}")
            e.cause?.message?.let(::println)
            exitProcess(1)
        }

        logger.info("Starting up ${Version.name} node ${Version.revision}")
        logger.info("CPU: ${Runtime.availableProcessors} cores ${System.getProperty("os.arch")}")
        logger.info("OS: ${System.getProperty("os.name")} ${System.getProperty("os.version")}")
        logger.info("VM: ${System.getProperty("java.vm.name")} ${System.getProperty("java.vm.version")}")

        if (!Runtime.windowsOS && System.getProperty("user.name") == "root")
            logger.warn("Running as root")

        if (Config.instance.debugcoroutines) {
            logger.warn("Installing debug probes...")
            DebugProbes.install()
            logger.warn("Node may work significally slower")
        }

        logger.info("Using config directory ${configDir.absolutePath}")
        logger.info("Using data directory ${dataDir.absolutePath}")

        LevelDB
        Salt
        BlockDB
        WalletDB
        LedgerDB
        PeerDB
        TxPool
        Node
        Staker

        /* Launch Blacknet RPC API server using Ktor.
         *
         * Blacknet RPC API server logic is implemented in
         * ninja.blacknet.rpc.RPCServer
         *
         * Ktor is a framework for building asynchronous servers and clients
         * in connected systems using the powerful Kotlin programming language.
         * https://ktor.io/
         *
         * Ktor configuration is stored in
         * rpc.conf for main network
         * rpcregtest.conf for regression testing mode
         * https://ktor.io/servers/engine.html
         *
         */
        if (Config.instance.rpcserver) {
            embeddedServer(
                Netty,
                commandLineEnvironment(arrayOf("-config=${File(configDir,
                    if (regtest)
                        "rpcregtest.conf"
                    else
                        "rpc.conf"
                )}"))
            ).start(wait = false)
        }

        ChainFetcher.run()
    }
}
