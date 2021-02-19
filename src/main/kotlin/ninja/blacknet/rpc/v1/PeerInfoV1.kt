/*
 * Copyright (c) 2018-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.rpc.v1

import kotlinx.serialization.Serializable
import ninja.blacknet.crypto.HashSerializer
import ninja.blacknet.db.LedgerDB
import ninja.blacknet.network.packet.ChainAnnounce
import ninja.blacknet.network.Connection
import ninja.blacknet.network.Node
import ninja.blacknet.util.HashMap

@Serializable
class PeerInfoV1(
        val peerId: Long,
        val remoteAddress: String,
        val localAddress: String,
        val timeOffset: Long,
        val ping: Long,
        val protocolVersion: Int,
        val agent: String,
        val state: String,
        val dosScore: Int,
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
                HashSerializer.encode(chain.chain),
                chain.cumulativeDifficulty.toString(),
                fork
        )

        companion object {
            fun get(chain: ChainAnnounce, forkCache: HashMap<ByteArray, Boolean>): ChainInfo {
                val cached = forkCache.get(chain.chain)
                return if (cached != null) {
                    ChainInfo(chain, cached)
                } else {
                    val fork = !LedgerDB.chainContains(chain.chain)
                    forkCache.put(chain.chain, fork)
                    ChainInfo(chain, fork)
                }
            }
        }
    }

    companion object {
        fun get(connection: Connection, forkCache: HashMap<ByteArray, Boolean>): PeerInfoV1 {
            return PeerInfoV1(
                    connection.peerId,
                    connection.remoteAddress.toString(),
                    connection.localAddress.toString(),
                    connection.timeOffset,
                    connection.ping,
                    connection.version,
                    connection.agent,
                    connection.state.name,
                    connection.dosScore(),
                    connection.feeFilter.toString(),
                    connection.connectedAt,
                    ChainInfo.get(connection.lastChain, forkCache),
                    connection.totalBytesRead,
                    connection.totalBytesWritten
            )
        }

        suspend fun getAll(): List<PeerInfoV1> {
            val forkCache = HashMap<ByteArray, Boolean>()
            return Node.connections.map { PeerInfoV1.get(it, forkCache) }
        }
    }
}
