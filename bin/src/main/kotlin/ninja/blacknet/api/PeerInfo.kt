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
            connection.lastPacketTime,
            connection.totalBytesRead,
            connection.totalBytesWritten
    )

    companion object {
        suspend fun getAll() = Node.connections.map { PeerInfo(it) }
    }
}
