/*
 * Copyright (c) 2018-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.network

import kotlinx.serialization.Serializable
import kotlinx.serialization.Serializer
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import ninja.blacknet.Config
import ninja.blacknet.codec.base.Base32
import ninja.blacknet.crypto.HashEncoder
import ninja.blacknet.crypto.SipHash.hashCode
import ninja.blacknet.crypto.encodeByteArray
import ninja.blacknet.serialization.bbf.BinaryDecoder
import ninja.blacknet.serialization.bbf.BinaryEncoder
import ninja.blacknet.serialization.notSupportedFormatError
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketAddress
import kotlin.experimental.and

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

    fun isLocal(): Boolean = when (network) {
        Network.IPv4 -> isLocalIPv4()
        Network.IPv6 -> isLocalIPv6()
        Network.TORv2, Network.TORv3 -> false
        Network.I2P -> false
    }

    fun isPrivate(): Boolean = when (network) {
        Network.IPv4 -> isPrivateIPv4()
        Network.IPv6 -> isPrivateIPv6()
        Network.TORv2, Network.TORv3 -> false
        Network.I2P -> false
    }

    fun getAddressString(): String = when (network) {
        Network.IPv4, Network.IPv6 -> InetSocketAddress(InetAddress.getByAddress(bytes), port.toPort()).getHostString()
        Network.TORv2 -> Base32.encode(bytes) + Network.TOR_SUFFIX
        Network.TORv3 -> Base32.encode(bytes + TorController.checksum(bytes, TorController.V3) + TorController.V3) + Network.TOR_SUFFIX
        Network.I2P -> Base32.encode(bytes) + Network.I2P_SUFFIX
    }

    fun getSocketAddress(): SocketAddress {
        return InetSocketAddress(InetAddress.getByAddress(bytes), port.toPort())
    }

    fun debugName(): String {
        return if (Config.instance.logips)
            toString()
        else
            "$network address"
    }

    override fun equals(other: Any?): Boolean {
        return (other is Address) && network == other.network && port == other.port && bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int {
        return hashCode(serializer(), this)
    }

    override fun toString(): String {
        return if (network != Network.IPv6)
            "${getAddressString()}:${port.toPort()}"
        else
            "[${getAddressString()}]:${port.toPort()}"
    }

    private fun isLocalIPv4(): Boolean {
        // 0.0.0.0 – 0.255.255.255
        if (bytes[0] == 0.toByte()) return true
        // 127.0.0.0 – 127.255.255.255
        if (bytes[0] == 127.toByte()) return true
        // 169.254.0.0 – 169.254.255.255
        if (bytes[0] == 169.toByte() && bytes[1] == 254.toByte()) return true

        return false
    }

    private fun isLocalIPv6(): Boolean {
        // ::
        if (bytes.contentEquals(Network.IPv6_ANY_BYTES)) return true
        // ::1
        if (bytes.contentEquals(Network.IPv6_LOOPBACK_BYTES)) return true
        // fe80:: - febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff
        if (       bytes[0] == 0xFE.toByte()
                && bytes[1] == 0x80.toByte()
                && bytes[2] == 0x00.toByte()
                && bytes[3] == 0x00.toByte()
                && bytes[4] == 0x00.toByte()
                && bytes[5] == 0x00.toByte()
                && bytes[6] == 0x00.toByte()
                && bytes[7] == 0x00.toByte()
        ) return true

        return false
    }

    private fun isPrivateIPv4(): Boolean {
        // 10.0.0.0 – 10.255.255.255
        if (bytes[0] == 10.toByte()) return true
        // 100.64.0.0 – 100.127.255.255
        if (bytes[0] == 100.toByte() && bytes[1] >= 64 && bytes[1] <= 127) return true
        // 172.16.0.0 – 172.31.255.255
        if (bytes[0] == 172.toByte() && bytes[1] >= 16 && bytes[1] <= 31) return true
        // 192.0.0.0 – 192.0.0.255
        if (bytes[0] == 192.toByte() && bytes[1] == 0.toByte() && bytes[2] == 0.toByte()) return true
        // 192.168.0.0 – 192.168.255.255
        if (bytes[0] == 192.toByte() && bytes[1] == 168.toByte()) return true
        // 198.18.0.0 – 198.19.255.255
        if (bytes[0] == 198.toByte() && bytes[1] >= 18 && bytes[1] <= 19) return true

        return false
    }

    private fun isPrivateIPv6(): Boolean {
        return bytes[0] and 0xFE.toByte() == 0xFC.toByte()
    }

    @Serializer(forClass = Address::class)
    companion object {
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
                else -> throw notSupportedFormatError(decoder, this)
            }
        }

        override fun serialize(encoder: Encoder, value: Address) {
            when (encoder) {
                is BinaryEncoder -> {
                    encoder.encodeByte(value.network.type)
                    encoder.encodeShort(value.port)
                    encoder.encodeFixedByteArray(value.bytes)
                }
                is HashEncoder -> {
                    encoder.encodeByte(value.network.type)
                    encoder.encodeShort(value.port)
                    encoder.encodeByteArray(value.bytes)
                }
                else -> throw notSupportedFormatError(encoder, this)
            }
        }
    }
}

@Serializable
internal class AddressV1(
        val network: Byte,
        val port: Int,
        val bytes: ByteArray
)
