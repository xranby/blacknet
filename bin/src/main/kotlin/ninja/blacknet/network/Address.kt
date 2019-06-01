/*
 * Copyright (c) 2018 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.network

import kotlinx.serialization.Serializable
import ninja.blacknet.Config
import ninja.blacknet.Config.port
import ninja.blacknet.serialization.SerializableByteArray
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketAddress

@Serializable
class Address(
        val network: Network,
        val port: Int,
        val bytes: SerializableByteArray
) {
    constructor(network: Network, port: Int, bytes: ByteArray) : this(network, port, SerializableByteArray(bytes))

    fun checkSize(): Boolean {
        return bytes.array.size == network.addrSize
    }

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
        return InetSocketAddress(InetAddress.getByAddress(bytes.array), port)
    }

    override fun equals(other: Any?): Boolean {
        return (other is Address) && network == other.network && port == other.port && bytes == other.bytes
    }

    override fun hashCode(): Int {
        return network.ordinal xor port xor bytes.hashCode()
    }

    override fun toString(): String {
        return getAddressString() + ':' + port
    }

    companion object {
        val LOOPBACK = Address.IPv4_LOOPBACK(Config[port])

        fun IPv4_ANY(port: Int) = Address(Network.IPv4, port, ByteArray(Network.IPv4.addrSize))
        fun IPv4_LOOPBACK(port: Int) = Address(Network.IPv4, port, Network.IPv4_LOOPBACK_BYTES)
        fun IPv6_ANY(port: Int) = Address(Network.IPv6, port, Network.IPv6_ANY_BYTES)
        fun IPv6_LOOPBACK(port: Int) = Address(Network.IPv6, port, Network.IPv6_LOOPBACK_BYTES)
    }
}