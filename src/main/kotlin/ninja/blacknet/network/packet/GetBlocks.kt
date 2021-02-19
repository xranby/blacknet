/*
 * Copyright (c) 2018-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.network.packet

import kotlinx.serialization.Serializable
import ninja.blacknet.crypto.HashSerializer
import ninja.blacknet.crypto.PoS
import ninja.blacknet.db.BlockDB
import ninja.blacknet.db.LedgerDB
import ninja.blacknet.network.Connection
import ninja.blacknet.network.Node

@Serializable
class GetBlocks(
        @Serializable(with = HashSerializer::class)
        private val best: ByteArray,
        @Serializable(with = HashSerializer::class)
        private val checkpoint: ByteArray
) : Packet {
    override suspend fun process(connection: Connection) {
        val cachedBlock = BlockDB.cachedBlock
        if (cachedBlock != null) {
            val (previousHash, bytes) = cachedBlock
            if (previousHash.contentEquals(best)) {
                connection.sendPacket(PacketType.Blocks, Blocks(emptyList(), listOf(bytes)))
                return
            }
        }

        var chainIndex = LedgerDB.getChainIndex(best)

        if (chainIndex == null) {
            val nextBlockHashes = LedgerDB.getNextBlockHashes(checkpoint, PoS.MATURITY)
            if (nextBlockHashes != null) {
                connection.sendPacket(PacketType.Blocks, Blocks(nextBlockHashes, emptyList()))
                return
            } else {
                connection.sendPacket(PacketType.ChainFork, ChainFork())
                connection.dos("Chain fork")
                return
            }
        }

        var size = PACKET_HEADER_SIZE_BYTES + 2 + 1
        val maxSize = Node.getMinPacketSize() // we don't know actual value, so assume minimum
        val response = ArrayList<ByteArray>()

        while (true) {
            if (chainIndex == null)
                break
            val hash = chainIndex.next
            if (hash.contentEquals(HashSerializer.ZERO))
                break
            size += chainIndex.nextSize + 4 //TODO VarInt.size()
            if (response.isNotEmpty() && size >= maxSize)
                break
            val bytes = BlockDB.get(hash)
            if (bytes == null)
                break
            response.add(bytes)
            chainIndex = LedgerDB.getChainIndex(hash)
        }

        connection.sendPacket(PacketType.Blocks, Blocks(emptyList(), response))
    }
}
