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
import ninja.blacknet.db.PeerDB
import ninja.blacknet.serialization.BinaryEncoder
import kotlin.random.Random

private val logger = KotlinLogging.logger {}

@Serializable
internal class Version(
        private val magic: Int,
        private val version: Int,
        private val time: Long,
        private val nonce: Long,
        private val agent: String,
        private val feeFilter: Long,
        private val chain: ChainAnnounce
) : Packet {
    override fun serialize(): ByteReadPacket = BinaryEncoder.toPacket(serializer(), this)

    override fun getType() = PacketType.Version

    override suspend fun process(connection: Connection) {
        connection.timeOffset = Node.time() - time
        connection.version = version
        connection.agent = Bip14.sanitize(agent)
        connection.feeFilter = feeFilter
        connection.lastChain = chain

        if (magic != Node.magic || version < Node.minVersion) {
            connection.close()
            return
        }

        if (connection.state == Connection.State.INCOMING_WAITING) {
            if (nonce == Node.nonce) {
                connection.close()
                return
            }
            if (version >= FIXED_NONCE_VERSION)
                Node.sendVersion(connection, nonce)
            else
                Node.sendVersion(connection, Random.nextLong())
            connection.state = Connection.State.INCOMING_CONNECTED
            logger.info("Accepted connection from ${connection.remoteAddress}")
        } else {
            connection.state = Connection.State.OUTGOING_CONNECTED
            PeerDB.connected(connection.remoteAddress)
            logger.info("Connected to ${connection.remoteAddress}")
        }

        ChainFetcher.offer(connection, chain.chain, chain.cumulativeDifficulty)
    }

    companion object {
        const val FIXED_NONCE_VERSION = 7
    }
}
