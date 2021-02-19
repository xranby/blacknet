/*
 * Copyright (c) 2018-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.network

import io.ktor.network.sockets.ASocket
import io.ktor.network.sockets.aSocket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.cancel
import io.ktor.utils.io.close
import io.ktor.utils.io.readUTF8Line
import io.ktor.utils.io.writeStringUtf8
import java.io.File
import java.io.FileOutputStream
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import mu.KotlinLogging
import ninja.blacknet.Config
import ninja.blacknet.Runtime
import ninja.blacknet.dataDir
import ninja.blacknet.core.currentTimeSeconds
import ninja.blacknet.crypto.HashEncoder.Companion.buildHash
import ninja.blacknet.crypto.encodeByteArray
import ninja.blacknet.logging.error
import ninja.blacknet.util.moveFile
import ninja.blacknet.util.sync

private val logger = KotlinLogging.logger {}

object TorController {
    private var privateKey = "NEW:BEST"

    init {
        try {
            val file = File(dataDir, "privateKey.tor")
            val readPrivateKey = file.readText()
            if (readPrivateKey.startsWith("RSA1024:")) {
                logger.info("Migration to Tor addresses version 3")
                val newName = "privateKey.${currentTimeSeconds()}.tor"
                moveFile(file, File(dataDir, newName))
                logger.info("Renamed private key file to $newName")
            } else {
                privateKey = readPrivateKey
            }
        } catch (e: Throwable) {
        }
    }

    class Connection(
            val socket: ASocket,
            val readChannel: ByteReadChannel,
            val writeChannel: ByteWriteChannel
    ) {
        suspend fun authenticate() {
            writeChannel.writeStringUtf8("AUTHENTICATE\r\n")
            val replyLine = readChannel.readUTF8Line()
            when (replyLine) {
                "250 OK" -> Unit
                null -> throw RuntimeException("Tor controller connection unexpectedly closed")
                else -> throw RuntimeException("Unknown Tor reply line $replyLine")
            }
        }

        suspend fun addOnion(): Pair<String?, String?> {
            writeChannel.writeStringUtf8("ADD_ONION $privateKey Port=${Config.instance.port.toPort().toPort()}\r\n")
            var serviceID: String? = null
            var newPrivateKey: String? = null
            while (true) {
                val replyLine = readChannel.readUTF8Line()
                if (replyLine == null)
                    throw RuntimeException("Tor controller connection unexpectedly closed")
                else if (replyLine == "250 OK")
                    break
                else if (replyLine.startsWith("250-ServiceID="))
                    serviceID = replyLine.drop(14)
                else if (replyLine.startsWith("250-PrivateKey="))
                    newPrivateKey = replyLine.drop(15)
                else if (!replyLine.startsWith("250-"))
                    throw RuntimeException("Unknown Tor reply line $replyLine")
            }
            return Pair(serviceID, newPrivateKey)
        }

        fun close() {
            socket.close()
            readChannel.cancel()
            writeChannel.close()
        }

        fun exception(message: String): Nothing {
            close()
            throw RuntimeException(message)
        }
    }

    suspend fun listen(): Pair<Job, Address> {
        //TODO configure host
        val socket = aSocket(Network.selector).tcp().connect(Address.IPv4_LOOPBACK(Config.instance.torcontrol.toPort()).getSocketAddress())
        val connection = Connection(socket, socket.openReadChannel(), socket.openWriteChannel(true))
        //TODO cookie, password
        connection.authenticate()
        val (serviceID, newPrivateKey) = connection.addOnion()
        val address = Network.parse(serviceID + Network.TOR_SUFFIX, Config.instance.port.toPort()) ?: connection.exception("Failed to parse Onion Service ID $serviceID")
        require(address.network == Network.TORv2 || address.network == Network.TORv3)

        if (privateKey.startsWith("NEW:"))
            savePrivateKey(newPrivateKey ?: connection.exception("Failed to get new private key"))

        return Pair(Runtime.launch {
            val replyLine = connection.readChannel.readUTF8Line()
            if (replyLine != null)
                connection.exception("Unknown Tor reply line $replyLine")
            else
                connection.close()
        }, address)
    }

    private fun savePrivateKey(privKey: String) {
        privateKey = privKey
        logger.info("Saving Tor private key")
        try {
            FileOutputStream(File(dataDir, "privateKey.tor")).sync {
                write(privateKey.toByteArray(Charsets.UTF_8))
            }
        } catch (e: Throwable) {
            logger.error(e)
        }
    }

    private const val CHECKSUM_CONST = ".onion checksum"
    const val V3: Byte = 3

    fun checksum(bytes: ByteArray, version: Byte): ByteArray {
        return buildHash("SHA3-256") {
            encodeString(CHECKSUM_CONST)
            encodeByteArray(bytes)
            encodeByte(version)
        }.copyOf(2)
    }
}
