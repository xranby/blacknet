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
import ninja.blacknet.crypto.Hash
import ninja.blacknet.serialization.BinaryEncoder

@Serializable
internal class Inventory(private val list: InvList) : Packet {
    override fun serialize(): ByteReadPacket = BinaryEncoder.toPacket(serializer(), this)

    override fun getType() = PacketType.Inventory

    override suspend fun process(connection: Connection) {
        if (Node.isInitialSynchronization())
            return

        if (list.size > DataType.MAX_INVENTORY) {
            connection.dos("invalid Inventory size")
            return
        }

        DataFetcher.offer(connection, list)
    }
}

typealias InvType = Pair<DataType, Hash>
typealias InvList = ArrayList<InvType>
typealias UnfilteredInvList = ArrayList<Triple<DataType, Hash, Long>>
