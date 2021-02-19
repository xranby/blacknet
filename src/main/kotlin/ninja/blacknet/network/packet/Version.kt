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
import mu.KotlinLogging
import ninja.blacknet.core.currentTimeSeconds
import ninja.blacknet.db.PeerDB
import ninja.blacknet.network.*

private val logger = KotlinLogging.logger {}

@Serializable
class Version(
        private val magic: Int,
        private val version: Int,
        private val time: Long,
        private val nonce: Long,
        private val agent: String,
        private val feeFilter: Long,
        private val chainAnnounce: ChainAnnounce
) : Packet {
    override suspend fun process(connection: Connection) {
        if (magic != Node.magic) {
            connection.close()
            return
        }

        connection.timeOffset = time - currentTimeSeconds()
        connection.peerId = Node.newPeerId()
        connection.version = version
        connection.agent = UserAgent.sanitize(agent)
        connection.feeFilter = feeFilter
        connection.lastChain = chainAnnounce

        if (version < Node.minVersion) {
            logger.info("Obsolete protocol version $version ${connection.debugName()} $agent")
            connection.close()
            return
        }

        if (connection.state == Connection.State.INCOMING_WAITING) {
            if (nonce != Node.nonce) {
                Node.sendVersion(connection, nonce, prober = false)
                connection.state = Connection.State.INCOMING_CONNECTED
                logger.info("Accepted connection from ${connection.debugName()} $agent")
            } else {
                connection.close()
                return
            }
        } else if (connection.state == Connection.State.OUTGOING_WAITING) {
            connection.state = Connection.State.OUTGOING_CONNECTED
            PeerDB.connected(connection.remoteAddress, connection.connectedAt, connection.agent, prober = false)
            logger.info("Connected to ${connection.debugName()} $agent")
        } else if (connection.state == Connection.State.PROBER_WAITING) {
            connection.state = Connection.State.PROBER_CONNECTED
            connection.close()
            PeerDB.connected(connection.remoteAddress, connection.connectedAt, connection.agent, prober = true)
            return
        } else {
            throw IllegalStateException("${connection.state}")
        }

        ChainFetcher.offer(connection, chainAnnounce)
    }
}
