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
import mu.KotlinLogging
import ninja.blacknet.core.DataDB.Status
import ninja.blacknet.core.DataType
import ninja.blacknet.core.TxPool
import ninja.blacknet.serialization.BinaryEncoder
import ninja.blacknet.serialization.SerializableByteArray

private val logger = KotlinLogging.logger {}

@Serializable
class Data(private val list: DataList) : Packet {
    override fun serialize(): ByteReadPacket = BinaryEncoder.toPacket(serializer(), this)

    override fun getType() = PacketType.Data

    override suspend fun process(connection: Connection) {
        if (list.size > DataType.MAX_DATA) {
            connection.dos("invalid Data size")
            return
        }

        val inv = UnfilteredInvList()

        for (i in list) {
            val type = i.first
            val bytes = i.second

            val hash = type.hash(bytes.array)

            if (!DataFetcher.fetched(hash)) {
                connection.dos("unrequested ${type.name} $hash")
                continue
            }

            val status = if (type == DataType.Transaction)
                TxPool.processTx(hash, bytes.array, connection)
            else
                Pair(type.db.process(hash, bytes.array, connection), 0L)

            when (status.first) {
                Status.ACCEPTED -> inv.add(Triple(type, hash, status.second))
                Status.INVALID -> connection.dos("invalid ${type.name} $hash")
                Status.IN_FUTURE -> logger.debug { "in future ${type.name} $hash" }
                Status.NOT_ON_THIS_CHAIN -> {
                    if (type == DataType.Block) ChainFetcher.offer(connection, hash)
                    else logger.debug { "not on this chain ${type.name} $hash" }
                }
                Status.ALREADY_HAVE -> logger.debug { "already have  ${type.name} $hash" }
            }
        }

        if (!inv.isEmpty())
            Node.broadcastInv(inv, connection)
    }
}

typealias DataList = ArrayList<Pair<DataType, SerializableByteArray>>
