/*
 * Copyright (c) 2018-2019 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.api

import kotlinx.serialization.Serializable
import ninja.blacknet.crypto.Hash
import ninja.blacknet.db.LedgerDB
import ninja.blacknet.packet.ChainAnnounce
import ninja.blacknet.network.Connection
import ninja.blacknet.network.Node

@Serializable
class PeerInfo(
        val peerId: Long,
        val remoteAddress: String,
        val localAddress: String,
        val timeOffset: Long,
        val ping: Long,
        val protocolVersion: Int,
        val agent: String,
        val outgoing: Boolean,
        val banScore: Int,
        val feeFilter: String,
        val connectedAt: Long,
        val lastChain: ChainInfo,
        val totalBytesRead: Long,
        val totalBytesWritten: Long
) {
    @Serializable
    class ChainInfo(
            val chain: String,
            val cumulativeDifficulty: String,
            val fork: Boolean
    ) {
        constructor(chain: ChainAnnounce, fork: Boolean) : this(
                chain.chain.toString(),
                chain.cumulativeDifficulty.toString(),
                fork
        )

        companion object {
            fun get(chain: ChainAnnounce, forkCache: HashMap<Hash, Boolean>): ChainInfo {
                val fork = forkCache.computeIfAbsent(chain.chain) { !LedgerDB.chainContains(it) }
                return ChainInfo(chain, fork)
            }
        }
    }

    companion object {
        fun get(connection: Connection, forkCache: HashMap<Hash, Boolean>): PeerInfo {
            return PeerInfo(
                    connection.peerId,
                    connection.remoteAddress.toString(),
                    connection.localAddress.toString(),
                    connection.timeOffset,
                    connection.ping,
                    connection.version,
                    connection.agent,
                    connection.state.isOutgoing(),
                    connection.dosScore(),
                    connection.feeFilter.toString(),
                    connection.connectedAt,
                    ChainInfo.get(connection.lastChain, forkCache),
                    connection.totalBytesRead,
                    connection.totalBytesWritten
            )
        }

        suspend fun getAll(): List<PeerInfo> {
            val forkCache = HashMap<Hash, Boolean>()
            forkCache.put(Hash.ZERO, false)
            return Node.connections.map { PeerInfo.get(it, forkCache) }
        }
    }
}
