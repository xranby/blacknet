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
import ninja.blacknet.crypto.Hash
import ninja.blacknet.serialization.BinaryEncoder
import ninja.blacknet.serialization.SerializableByteArray

@Serializable
class Blocks(
        internal val hashes: ArrayList<Hash>,
        internal val blocks: ArrayList<SerializableByteArray>
) : Packet {
    override fun serialize(): ByteReadPacket = BinaryEncoder.toPacket(serializer(), this)

    override fun getType() = PacketType.Blocks

    fun isEmpty(): Boolean {
        return hashes.isEmpty() && blocks.isEmpty()
    }

    override suspend fun process(connection: Connection) {
        ChainFetcher.fetched(connection, this)
    }
}
