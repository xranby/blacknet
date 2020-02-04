/*
 * Copyright (c) 2018-2019 Pavel Vasin
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
import io.ktor.util.error
import kotlinx.coroutines.io.ByteReadChannel
import kotlinx.coroutines.io.ByteWriteChannel
import kotlinx.coroutines.io.readUTF8Line
import kotlinx.coroutines.io.writeStringUtf8
import kotlinx.coroutines.launch
import mu.KotlinLogging
import ninja.blacknet.Config
import ninja.blacknet.Config.i2psamhost
import ninja.blacknet.Config.i2psamport
import ninja.blacknet.Runtime
import ninja.blacknet.crypto.Base64
import ninja.blacknet.crypto.SHA256
import java.io.File
import kotlin.random.Random

private val logger = KotlinLogging.logger {}

object I2PSAM {
    private var privateKey = "TRANSIENT"
    private val sam: Address?
    @Volatile
    private var session: Pair<String, Address>? = null

    init {
        if (Config.contains(i2psamhost) && Config.contains(i2psamport))
            sam = Network.resolve(Config[i2psamhost], Config[i2psamport].toPort())
        else
            sam = null

        try {
            val file = File(Config.dataDir, "privateKey.i2p")
            val lastModified = file.lastModified()
            if (lastModified != 0L && lastModified < 1550000000000) {
                if (file.renameTo(File(Config.dataDir, "privateKey.$lastModified.i2p")))
                    logger.info("Renamed private key file to privateKey.$lastModified.i2p")
            } else {
                privateKey = file.readText()
            }
        } catch (e: Throwable) {
        }
    }

    fun session(): Pair<String, Address> {
        return session ?: throw I2PException("session is not available")
    }

    private suspend fun connectToSAM(): Connection {
        val socket = aSocket(Network.selector).tcp().connect(sam?.getSocketAddress() ?: throw NotConfigured)
        val connection = Connection(socket, socket.openReadChannel(), socket.openWriteChannel(true))

        val answer = request(connection, "HELLO VERSION MIN=3.2\n")
        connection.checkResult(answer)

        return connection
    }

    suspend fun createSession(): Pair<String, Address> {
        val connection = connectToSAM()

        val sessionId = generateId()

        val answer = request(connection, "SESSION CREATE STYLE=STREAM ID=$sessionId DESTINATION=$privateKey SIGNATURE_TYPE=EdDSA_SHA512_Ed25519\n")
        connection.checkResult(answer)
        val privateKey = getValue(answer, "DESTINATION") ?: throw I2PException("invalid response")

        val destination = lookup(connection, "ME")
        val localAddress = Address(Network.I2P, Config.netPort, hash(destination))

        if (this.privateKey == "TRANSIENT")
            savePrivateKey(privateKey)

        val newSession = Pair(sessionId, localAddress)
        session = newSession

        Runtime.launch {
            while (true) {
                val message = connection.readChannel.readUTF8Line() ?: break

                if (message.startsWith("PING")) {
                    connection.writeChannel.writeStringUtf8("PONG" + message.drop(4) + '\n')
                }
            }
            session = null
        }

        return newSession
    }

    suspend fun connect(address: Address): Connection {
        val (sessionId, _) = session()

        val connection = connectToSAM()

        val destination = lookup(connection, address.getAddressString())

        val answer = request(connection, "STREAM CONNECT ID=$sessionId DESTINATION=$destination\n")
        connection.checkResult(answer)

        return connection
    }

    suspend fun accept(): Accepted {
        val (sessionId, _) = session()

        val connection = connectToSAM()

        val answer = request(connection, "STREAM ACCEPT ID=$sessionId\n")
        try {
            connection.checkResult(answer)
        } catch (e: Throwable) {
            logger.info("STREAM ACCEPT failed: ${e.message}")
            throw e
        }

        while (true) {
            val message = connection.readChannel.readUTF8Line() ?: throw I2PException("connection closed")

            if (message.startsWith("PING")) {
                connection.writeChannel.writeStringUtf8("PONG" + message.drop(4) + '\n')
            } else {
                val destination = message.takeWhile { it != ' ' }
                val remoteAddress = Address(Network.I2P, Config.netPort, hash(destination))
                return Accepted(connection.socket, connection.readChannel, connection.writeChannel, remoteAddress)
            }
        }
    }

    private suspend fun lookup(connection: Connection, name: String): String {
        val answer = request(connection, "NAMING LOOKUP NAME=$name\n")
        connection.checkResult(answer)
        return getValue(answer, "VALUE")!!
    }

    private suspend fun request(connection: Connection, request: String): String? {
        logger.debug { request.dropLast(1) }
        connection.writeChannel.writeStringUtf8(request)
        val answer = connection.readChannel.readUTF8Line()
        logger.debug { "$answer" }
        return answer
    }

    private fun hash(destination: String) = SHA256.hash(Base64.decode(destination, i2p = true)!!)

    private fun generateId(): String {
        val size = 8
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        val builder = StringBuilder()
        for (i in 1..size) {
            val rnd = Random.nextInt(alphabet.length)
            builder.append(alphabet[rnd])
        }
        return builder.toString()
    }

    private fun getValue(answer: String?, key: String): String? {
        if (answer == null) return null
        val keyPattern = ' ' + key + '='
        val i = answer.indexOf(keyPattern)
        if (i == -1)
            return null
        val valueStart = i + keyPattern.length
        if (valueStart == answer.length)
            return String()
        if (answer[valueStart] == '"')
            return answer.substring(valueStart + 1, answer.indexOf('"', valueStart + 1))
        val valueEnd = answer.indexOf(' ', valueStart)
        if (valueEnd == -1)
            return answer.substring(valueStart)
        return answer.substring(valueStart, valueEnd)
    }

    class Connection(val socket: ASocket, val readChannel: ByteReadChannel, val writeChannel: ByteWriteChannel) {
        internal fun checkResult(answer: String?) {
            if (answer == null)
                exception("connection closed")
            val result = getValue(answer, "RESULT")
            if (result == null) {
                exception("No RESULT")
            } else if (result.isEmpty()) {
                exception("Empty RESULT")
            } else if (result != "OK") {
                val message = getValue(answer, "MESSAGE")
                if (message != null && !message.isEmpty())
                    exception("$result $message")
                else
                    exception(result)
            }
        }

        private fun exception(message: String) {
            socket.close()
            throw I2PException(message)
        }
    }

    class Accepted(val socket: ASocket, val readChannel: ByteReadChannel, val writeChannel: ByteWriteChannel, val remoteAddress: Address)
    open class I2PException(message: String) : RuntimeException("I2P SAM $message")
    object NotConfigured : I2PException("is not configured")

    private fun savePrivateKey(dest: String) {
        privateKey = dest
        logger.info("Saving I2P private key")
        try {
            File(Config.dataDir, "privateKey.i2p").writeText(privateKey)
        } catch (e: Throwable) {
            logger.error(e)
        }
    }
}
