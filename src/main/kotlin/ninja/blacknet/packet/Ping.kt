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
import ninja.blacknet.network.Connection
import ninja.blacknet.network.Pinger
import ninja.blacknet.serialization.BinaryEncoder

@Serializable
class Ping(
        val challenge: Int
) : Packet {
    override fun serialize(): ByteReadPacket = BinaryEncoder.toPacket(serializer(), this)

    override fun getType() = PacketType.Ping

    override suspend fun process(connection: Connection) {
        Pinger.ping(connection, this)
    }
}
