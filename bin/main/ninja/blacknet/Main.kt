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
import io.ktor.server.cio.CIO
import io.ktor.server.engine.commandLineEnvironment
import io.ktor.server.engine.embeddedServer
import mu.KotlinLogging
import ninja.blacknet.db.*
import ninja.blacknet.network.Node
import java.io.FileInputStream
import java.security.Security
import java.util.logging.LogManager

private val logger = KotlinLogging.logger {}

object Main {
    @JvmStatic
    fun main(args: Array<String>) {
        Security.addProvider(Blake2bProvider())

        val inStream = FileInputStream("config/logging.properties")
        LogManager.getLogManager().readConfiguration(inStream)
        inStream.close()

        logger.info("Starting Blacknet node")

        if (System.getProperty("user.name") == "root")
            logger.warn("Running as root")

        if (Config.portable())
            logger.info("Portable mode")
        logger.info("Using data directory ${Config.dataDir}")

        LevelDB
        BlockDB
        LedgerDB
        PeerDB
        Node
        WalletDB

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
        if (Config.publicapi())
            embeddedServer(CIO, commandLineEnvironment(arrayOf("-config=config/ktor.conf"))).start(wait = false)
        embeddedServer(CIO, commandLineEnvironment(arrayOf("-config=config/rpc.conf"))).start(wait = true)
    }
}
