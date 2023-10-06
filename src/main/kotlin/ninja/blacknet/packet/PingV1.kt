/*
 * Copyright (c) 2018-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.packet

import com.google.common.primitives.Ints
import kotlinx.io.core.ByteReadPacket
import kotlinx.serialization.Serializable
import ninja.blacknet.crypto.Blake2b
import ninja.blacknet.network.Connection
import ninja.blacknet.network.Node
import ninja.blacknet.serialization.BinaryEncoder

@Serializable
class PingV1(
    val challenge: Int
) : Packet {
    override fun serialize(): ByteReadPacket = BinaryEncoder.toPacket(serializer(), this)

    override fun getType() = PacketType.PingV1

    override suspend fun process(connection: Connection) {
        connection.sendPacket(Pong(if (connection.version == 13) solveV1(challenge) else challenge))
        val lastPacketTime = connection.lastPacketTime
        val lastPingTime = connection.lastPingTime
        connection.lastPingTime = lastPacketTime
        if (lastPacketTime > lastPingTime + Node.NETWORK_TIMEOUT / 2)
            Unit
        else
            connection.dos("Too many ping requests")
    }
}

fun solveV1(challenge: Int): Int {
    val hash = Blake2b.hasher { this + Node.magic + challenge }
    return Ints.fromBytes(hash.bytes[0], hash.bytes[1], hash.bytes[2], hash.bytes[3])
}
