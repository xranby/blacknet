/*
 * Copyright (c) 2018 Pavel Vasin
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
import kotlinx.coroutines.io.ByteReadChannel
import kotlinx.coroutines.io.ByteWriteChannel
import kotlinx.coroutines.io.readFully
import kotlinx.io.core.BytePacketBuilder
import kotlinx.io.core.Closeable
import kotlinx.io.core.writeFully

class Socks5(private val proxy: Address) {
    suspend fun connect(address: Address): Connection {
        val socket = aSocket(Network.selector).tcp().connect(proxy.getSocketAddress())
        val readChannel = socket.openReadChannel()
        val writeChannel = socket.openWriteChannel(true)
        val builder = BytePacketBuilder()

        builder.writeByte(VERSION)
        builder.writeByte(1) // number of authentication methods supported
        builder.writeByte(NO_AUTHENTICATION)
        writeChannel.writePacket(builder.build())

        if (readChannel.readByte() != VERSION) {
            return error(socket, "unknown socks version")
        }
        if (readChannel.readByte() != NO_AUTHENTICATION) {
            return error(socket, "socks auth not accepted")
        }

        builder.writeByte(VERSION)
        builder.writeByte(TCP_CONNECTION)
        builder.writeByte(0) // reserved
        when (address.network) {
            Network.IPv4 -> {
                builder.writeByte(IPv4_ADDRESS)
                builder.writeFully(address.bytes.array)
            }
            Network.IPv6 -> {
                builder.writeByte(IPv6_ADDRESS)
                builder.writeFully(address.bytes.array)
            }
            Network.TORv2, Network.TORv3 -> {
                val bytes = address.getAddressString().toByteArray(Charsets.US_ASCII)
                if (bytes.size < 1 || bytes.size > 255)
                    return error(socket, "invalid length of domain name")
                builder.writeByte(DOMAIN_NAME)
                builder.writeByte(bytes.size.toByte())
                builder.writeFully(bytes)
            }
            else -> return error(socket, "not implemented for ${address.network}")
        }
        builder.writeShort(address.port.toShort())
        writeChannel.writePacket(builder.build())

        if (readChannel.readByte() != VERSION) {
            return error(socket, "unknown socks version")
        }
        if (readChannel.readByte() != REQUEST_GRANTED) {
            return error(socket, "connection failed")
        }
        if (readChannel.readByte() != 0.toByte()) {
            return error(socket, "invalid socks response")
        }
        val addrType = readChannel.readByte()
        when (addrType) {
            IPv4_ADDRESS -> readChannel.skip(4 + 2)
            IPv6_ADDRESS -> readChannel.skip(16 + 2)
            DOMAIN_NAME -> readChannel.skip(readChannel.readByte().toInt() + 2)
            else -> return error(socket, "unknown socks response")
        }

        return Connection(socket, readChannel, writeChannel)
    }

    private fun error(closeable: Closeable, message: String): Connection {
        closeable.close()
        throw RuntimeException(message)
    }

    class Connection(val socket: ASocket, val readChannel: ByteReadChannel, val writeChannel: ByteWriteChannel)

    companion object {
        const val VERSION = 5.toByte()
        const val NO_AUTHENTICATION = 0.toByte()
        const val TCP_CONNECTION = 1.toByte()
        const val REQUEST_GRANTED = 0.toByte()
        const val IPv4_ADDRESS = 1.toByte()
        const val DOMAIN_NAME = 3.toByte()
        const val IPv6_ADDRESS = 4.toByte()
    }
}

private suspend fun ByteReadChannel.skip(num: Int) {
    readFully(ByteArray(num))
}
