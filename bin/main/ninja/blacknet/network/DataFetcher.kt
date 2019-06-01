/*
 * Copyright (c) 2018 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.network

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import ninja.blacknet.core.DataType
import ninja.blacknet.crypto.Hash
import ninja.blacknet.util.SynchronizedHashMap
import ninja.blacknet.util.delay

object DataFetcher {
    private val inventoryChannel: Channel<Pair<Connection, InvList>> = Channel(Channel.UNLIMITED)
    private val requested = SynchronizedHashMap<Hash, Long>()

    init {
        Node.launch { fetcher() }
        Node.launch { watchdog() }
    }

    fun offer(from: Connection, list: InvList) {
        inventoryChannel.offer(Pair(from, list))
    }

    suspend fun fetched(hash: Hash): Boolean {
        return requested.remove(hash) != null
    }

    private suspend fun fetcher() {
        for (inventory in inventoryChannel) {
            val connection = inventory.first
            val list = inventory.second

            val request = InvList()
            val currTime = Node.time()

            for (i in list) {
                val type = i.first
                val hash = i.second

                if (connection.version >= ChainAnnounce.MIN_VERSION && type == DataType.Block)
                    continue

                if (requested.containsKey(hash))
                    continue

                if (type.db.isInteresting(hash)) {
                    requested.put(hash, currTime)
                    request.add(Pair(type, hash))
                }

                if (request.size == DataType.MAX_DATA) {
                    connection.sendPacket(GetData(request))
                    request.clear()
                }
            }

            if (request.size == 0)
                continue

            connection.sendPacket(GetData(request))
        }
    }

    private suspend fun watchdog() {
        while (true) {
            delay(Node.NETWORK_TIMEOUT)

            val currTime = Node.time()
            val timeouted = requested.filterToKeyList { _, time -> currTime > time + Node.NETWORK_TIMEOUT }
            requested.removeAll(timeouted)
        }
    }
}
