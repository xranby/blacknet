/*
 * Copyright (c) 2019 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.network

import kotlinx.io.core.ByteReadPacket
import kotlinx.serialization.Serializable
import ninja.blacknet.crypto.BigInt
import ninja.blacknet.crypto.Hash
import ninja.blacknet.serialization.BinaryEncoder

@Serializable
class ChainAnnounce(
        private val chain: Hash,
        private val cumulativeDifficulty: BigInt
) : Packet {
    override fun serialize(): ByteReadPacket = BinaryEncoder.toPacket(serializer(), this)

    override fun getType() = PacketType.ChainAnnounce

    override suspend fun process(connection: Connection) {
        ChainFetcher.offer(connection, chain, cumulativeDifficulty)
    }

    companion object {
        const val MIN_VERSION = 6
    }
}
