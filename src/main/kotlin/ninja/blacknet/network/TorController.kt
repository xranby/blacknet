/*
 * Copyright (c) 2018-2019 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.network

import io.ktor.util.error
import mu.KotlinLogging
import net.freehaven.tor.control.TorControlCommands
import net.freehaven.tor.control.TorControlConnection
import net.freehaven.tor.control.TorControlError
import ninja.blacknet.Config
import ninja.blacknet.Config.torcontrol
import ninja.blacknet.util.emptyByteArray
import org.bouncycastle.crypto.digests.SHA3Digest
import java.io.File

private val logger = KotlinLogging.logger {}

object TorController {
    private var privateKey = "NEW:BEST"

    init {
        try {
            val file = File(Config.dataDir, "privateKey.tor")
            val lastModified = file.lastModified()
            if (lastModified != 0L && lastModified < 1566666666000) {
                if (file.renameTo(File(Config.dataDir, "privateKey.$lastModified.tor")))
                    logger.info("Renamed private key file to privateKey.$lastModified.tor")
            } else {
                privateKey = file.readText()
            }
        } catch (e: Throwable) {
        }
    }

    fun listen(): Pair<Thread, Address> {
        //TODO configure host
        val s = java.net.Socket("localhost", Config[torcontrol].toPort().toPort())
        val tor = TorControlConnection(s)
        val thread = tor.launchThread(true)
        //TODO cookie, password
        tor.authenticate(emptyByteArray())

        val request = HashMap<Int, String?>()
        request[Config.netPort.toPort()] = null

        val response = tor.addOnion(privateKey, request)
        val string = response[TorControlCommands.HS_ADDRESS] ?: throw TorControlError("Failed to get address")
        val address = Network.parse(string + Network.TOR_SUFFIX, Config.netPort) ?: throw TorControlError("Failed to parse address $string")

        when (address.network) {
            Network.TORv2, Network.TORv3 -> Unit
            else -> throw TorControlError("Unknown network type ${address.network}")
        }

        if (privateKey.startsWith("NEW:"))
            savePrivateKey(response[TorControlCommands.HS_PRIVKEY] ?: throw TorControlError("Failed to get private key"))

        return Pair(thread, address)
    }

    private fun savePrivateKey(privKey: String) {
        privateKey = privKey
        logger.info("Saving Tor private key")
        try {
            File(Config.dataDir, "privateKey.tor").writeText(privateKey)
        } catch (e: Throwable) {
            logger.error(e)
        }
    }

    private val CHECKSUM_CONST = ".onion checksum".toByteArray()
    const val V3: Byte = 3

    fun checksum(bytes: ByteArray, version: Byte): ByteArray {
        val digest = SHA3Digest(256)
        digest.update(CHECKSUM_CONST, 0, CHECKSUM_CONST.size)
        digest.update(bytes, 0, bytes.size)
        digest.update(version)
        val result = ByteArray(32)
        digest.doFinal(result, 0)
        return result.copyOf(2)
    }
}
