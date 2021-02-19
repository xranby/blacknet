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
import ninja.blacknet.db.PeerDB
import ninja.blacknet.network.Address
import ninja.blacknet.network.Connection

private val logger = KotlinLogging.logger {}

@Serializable
class Peers(
        private val list: ArrayList<Address>
) : Packet {
    override suspend fun process(connection: Connection) {
        if (list.size > MAX) {
            connection.dos("Invalid Peers size")
            return
        }

        val added = PeerDB.add(list, connection.remoteAddress)
        if (added > 0) {
            logger.info("$added new peer addresses from ${connection.debugName()}")
        }
    }

    companion object {
        const val MAX = 1000
    }
}
