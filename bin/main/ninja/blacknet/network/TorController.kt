/*
 * Copyright (c) 2018 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.network

import io.ktor.util.error
import kotlinx.coroutines.launch
import mu.KotlinLogging
import net.freehaven.tor.control.TorControlCommands
import net.freehaven.tor.control.TorControlConnection
import net.freehaven.tor.control.TorControlError
import net.i2p.data.Base32
import ninja.blacknet.Config
import java.io.File

private val logger = KotlinLogging.logger {}

object TorController {
    private var privateKey = "NEW:RSA1024"

    init {
        try {
            val file = File(Config.dataDir + "/privateKey.tor")
            val lastModified = file.lastModified()
            if (lastModified != 0L && lastModified < 1549868177000)
                file.renameTo(File(Config.dataDir + "/privateKey.$lastModified.tor"))
            privateKey = File(Config.dataDir + "/privateKey.tor").readText()
        } catch (e: Throwable) {
        }
    }

    fun listen(): Address? {
        val s = java.net.Socket("localhost", Config[Config.torcontrol])
        val tor = TorControlConnection(s)
        val thread = tor.launchThread(true)
        //TODO cookie, password
        tor.authenticate(ByteArray(0))

        val request = HashMap<Int, String?>()
        request[Config[Config.port]] = null

        val response = tor.addOnion(privateKey, request)
        val string = response[TorControlCommands.HS_ADDRESS]!!
        val bytes = Base32.decode(string)!!

        if (bytes.size != Network.TORv2.addrSize)
            throw TorControlError("Unknown KeyType")

        if (privateKey == "NEW:RSA1024")
            savePrivateKey(response[TorControlCommands.HS_PRIVKEY]!!)

        val address = Address(Network.TORv2, Config[Config.port], bytes)

        Node.launch {
            thread.join()
            Node.listenAddress.remove(address)
            logger.info("lost connection to tor controller")
            //TODO reconnect
        }

        return address
    }

    private fun savePrivateKey(privKey: String) {
        privateKey = privKey
        logger.info("Saving Tor private key")
        try {
            File(Config.dataDir + "/privateKey.tor").writeText(privateKey)
        } catch (e: Throwable) {
            logger.error(e)
        }
    }
}
