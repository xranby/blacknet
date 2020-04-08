/*
 * Copyright (c) 2018-2019 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.network

import kotlinx.serialization.Decoder
import kotlinx.serialization.Encoder
import kotlinx.serialization.Serializable
import kotlinx.serialization.Serializer
import ninja.blacknet.Config
import ninja.blacknet.serialization.BinaryDecoder
import ninja.blacknet.serialization.BinaryEncoder
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketAddress

/**
 * Network address
 */
@Serializable
class Address(
        val network: Network,
        val port: Short,
        val bytes: ByteArray
) {
    internal constructor(address: AddressV1) : this(Network.get(address.network), address.port.toPort(), address.bytes)

    fun isLocal(): Boolean {
        return network.isLocal(this)
    }

    fun isPrivate(): Boolean {
        return network.isPrivate(this)
    }

    fun getAddressString(): String {
        return network.getAddressString(this)
    }

    fun getSocketAddress(): SocketAddress {
        return InetSocketAddress(InetAddress.getByAddress(bytes), port.toPort())
    }

    fun debugName(): String {
        return if (Config.logIPs)
            toString()
        else
            "$network address"
    }

    override fun equals(other: Any?): Boolean {
        return (other is Address) && network == other.network && port == other.port && bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int {
        return network.ordinal xor port.toInt() xor bytes.contentHashCode()
    }

    override fun toString(): String {
        return getAddressString() + ':' + port.toPort()
    }

    @Serializer(forClass = Address::class)
    companion object {
        val LOOPBACK = Address.IPv4_LOOPBACK(Config.netPort)

        fun IPv4_ANY(port: Short) = Address(Network.IPv4, port, ByteArray(Network.IPv4.addrSize))
        fun IPv4_LOOPBACK(port: Short) = Address(Network.IPv4, port, Network.IPv4_LOOPBACK_BYTES)
        fun IPv6_ANY(port: Short) = Address(Network.IPv6, port, Network.IPv6_ANY_BYTES)
        fun IPv6_LOOPBACK(port: Short) = Address(Network.IPv6, port, Network.IPv6_LOOPBACK_BYTES)

        override fun deserialize(decoder: Decoder): Address {
            return when (decoder) {
                is BinaryDecoder -> {
                    val network = Network.get(decoder.decodeByte())
                    Address(network,
                            decoder.decodeShort(),
                            decoder.decodeFixedByteArray(network.addrSize))
                }
                else -> throw RuntimeException("Unsupported decoder")
            }
        }

        override fun serialize(encoder: Encoder, obj: Address) {
            when (encoder) {
                is BinaryEncoder -> {
                    encoder.encodeByte(obj.network.type)
                    encoder.encodeShort(obj.port)
                    encoder.encodeFixedByteArray(obj.bytes)
                }
                else -> throw RuntimeException("Unsupported encoder")
            }
        }
    }
}

@Serializable
internal class AddressV1(
        val network: Byte,
        val port: Int,
        val bytes: ByteArray
) {
    constructor(address: Address) : this(address.network.type, address.port.toPort(), address.bytes)

    fun check() = require(bytes.size == Network.get(network).addrSize) { "Invalid address size" }
}
