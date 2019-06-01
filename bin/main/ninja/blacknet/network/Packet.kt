/*
 * Copyright (c) 2018 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.network

import kotlinx.io.core.BytePacketBuilder
import kotlinx.io.core.ByteReadPacket

interface Packet {
    fun serialize(): ByteReadPacket
    fun getType(): PacketType
    suspend fun process(connection: Connection)

    fun build(): ByteReadPacket {
        val s = serialize()
        val b = BytePacketBuilder()
        b.writeInt(s.remaining.toInt() + 4)
        b.writeInt(getType().ordinal)
        b.writePacket(s)
        return b.build()
    }
}
