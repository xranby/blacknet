/*
 * Copyright (c) 2018-2019 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.packet

import kotlinx.io.core.ByteReadPacket
import kotlinx.serialization.Serializable
import ninja.blacknet.Runtime
import ninja.blacknet.network.Connection
import ninja.blacknet.serialization.BinaryEncoder

@Serializable
class Pong(
    private val response: Int
) : Packet {
    override fun serialize(): ByteReadPacket = BinaryEncoder.toPacket(serializer(), this)

    override fun getType() = PacketType.Pong

    override suspend fun process(connection: Connection) {
        val (challenge, requestTime) = connection.pingRequest ?: return connection.dos("Unexpected Pong")

        val solution = if (connection.version >= Ping.MIN_VERSION)
            solve(challenge)
        else if (connection.version == 13)
            solveV1(challenge)
        else
            challenge

        if (response != solution) {
            connection.dos("Invalid Pong")
            return
        }

        connection.ping = Runtime.timeMilli() - requestTime
        connection.pingRequest = null
    }
}
