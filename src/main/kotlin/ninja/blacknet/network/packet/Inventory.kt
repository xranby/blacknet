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
import ninja.blacknet.crypto.HashSerializer
import ninja.blacknet.network.Connection
import ninja.blacknet.network.TxFetcher
import ninja.blacknet.network.Node

@Serializable
class Inventory(
        private val list: List<@Serializable(HashSerializer::class) ByteArray>
) : Packet {
    override suspend fun process(connection: Connection) {
        if (list.size > MAX) {
            connection.dos("Invalid Inventory size ${list.size}")
            return
        }

        if (Node.isInitialSynchronization())
            return

        TxFetcher.offer(connection, list)
    }

    companion object {
        const val MAX = 50000
        const val SEND_MAX = 512
        const val SEND_TIMEOUT = 5 * 1000L
    }
}

typealias UnfilteredInvList = ArrayList<Pair<ByteArray, Long>>
