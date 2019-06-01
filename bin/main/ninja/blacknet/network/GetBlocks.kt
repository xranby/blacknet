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
import ninja.blacknet.core.PoS
import ninja.blacknet.crypto.Hash
import ninja.blacknet.db.BlockDB
import ninja.blacknet.db.LedgerDB
import ninja.blacknet.serialization.BinaryEncoder
import ninja.blacknet.serialization.SerializableByteArray

private val logger = KotlinLogging.logger {}

@Serializable
class GetBlocks(
        private val best: Hash,
        private val checkpoint: Hash
) : Packet {
    override fun serialize(): ByteReadPacket = BinaryEncoder.toPacket(serializer(), this)

    override fun getType() = PacketType.GetBlocks

    override suspend fun process(connection: Connection) {
        if (checkpoint != Hash.ZERO) {
            if (!LedgerDB.chainContains(checkpoint)) {
                logger.info("Chain fork ${connection.remoteAddress}")
                if (connection.version >= ChainFork.MIN_VERSION)
                    connection.sendPacket(ChainFork())
                connection.close(false)
                return
            }
        }

        if (best != Hash.ZERO && !LedgerDB.chainContains(best)) {
            val response = LedgerDB.getNextBlockHashes(checkpoint, PoS.MATURITY)
            connection.sendPacket(Blocks(response, ArrayList()))
            return
        }

        var chainIndex = LedgerDB.getChainIndex(best)
        if (chainIndex == null) {
            connection.sendPacket(Blocks(ArrayList(), ArrayList()))
            return
        }

        val maxSize = Node.getMinPacketSize() // we don't know actual value, so assume minimum
        val response = ArrayList<SerializableByteArray>()

        var size = 8

        while (true) {
            val hash = chainIndex!!.next
            if (hash == Hash.ZERO)
                break
            size += chainIndex.nextSize + 4 //TODO
            if (response.isNotEmpty() && size >= maxSize)
                break
            val bytes = BlockDB.get(hash)
            if (bytes == null)
                break
            response.add(SerializableByteArray(bytes))
            chainIndex = LedgerDB.getChainIndex(chainIndex.next)
        }

        connection.sendPacket(Blocks(ArrayList(), response))
    }
}
