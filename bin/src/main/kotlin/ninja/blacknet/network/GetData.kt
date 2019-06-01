/*
 * Copyright (c) 2018 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.network

import kotlinx.io.core.ByteReadPacket
import kotlinx.serialization.Serializable
import ninja.blacknet.core.DataType
import ninja.blacknet.serialization.BinaryEncoder
import ninja.blacknet.serialization.SerializableByteArray

@Serializable
class GetData(private val list: InvList) : Packet {
    override fun serialize(): ByteReadPacket = BinaryEncoder.toPacket(serializer(), this)

    override fun getType() = PacketType.GetData

    override suspend fun process(connection: Connection) {
        if (list.size > DataType.MAX_DATA) {
            connection.dos("invalid GetData size")
            return
        }

        val response = DataList()

        for (i in list) {
            val type = i.first
            val hash = i.second

            val value = type.db.get(hash) ?: continue
            response.add(Pair(type, SerializableByteArray(value)))
        }

        if (response.size == 0)
            return

        connection.sendPacket(Data(response))
    }
}