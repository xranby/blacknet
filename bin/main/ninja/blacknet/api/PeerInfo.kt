/*
 * Copyright (c) 2018 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.api

import kotlinx.serialization.Serializable
import ninja.blacknet.db.LedgerDB
import ninja.blacknet.network.ChainAnnounce
import ninja.blacknet.network.Connection
import ninja.blacknet.network.Node

@Serializable
class PeerInfo(
        val remoteAddress: String,
        val localAddress: String,
        val timeOffset: Long,
        val ping: Long,
        val protocolVersion: Int,
        val agent: String,
        val state: String,
        val dosScore: Int,
        val feeFilter: Long,
        val connectedAt: Long,
        val lastChain: ChainInfo,
        val lastPacketTime: Long,
        val totalBytesRead: Long,
        val totalBytesWritten: Long
) {
    constructor(connection: Connection) : this(
            connection.remoteAddress.toString(),
            connection.localAddress.toString(),
            connection.timeOffset,
            connection.ping,
            connection.version,
            connection.agent,
            connection.state.name,
            connection.dosScore(),
            connection.feeFilter,
            connection.connectedAt,
            ChainInfo.get(connection.lastChain),
            connection.lastPacketTime,
            connection.totalBytesRead,
            connection.totalBytesWritten
    )

    @Serializable
    class ChainInfo(
            val chain: String,
            val cumulativeDifficulty: String,
            val fork: Boolean
    ) {
        companion object {
            fun get(chain: ChainAnnounce): ChainInfo {
                return ChainInfo(chain.chain.toString(), chain.cumulativeDifficulty.toString(), !LedgerDB.chainContains(chain.chain))
            }
        }
    }

    companion object {
        suspend fun getAll() = Node.connections.map { PeerInfo(it) }
    }
}
