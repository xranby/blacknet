/*
 * Copyright (c) 2018-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.network

import kotlinx.coroutines.delay
import kotlinx.coroutines.channels.Channel
import ninja.blacknet.Runtime
import ninja.blacknet.core.TxPool
import ninja.blacknet.core.currentTimeMillis
import ninja.blacknet.network.packet.GetTransactions
import ninja.blacknet.network.packet.PacketType
import ninja.blacknet.network.packet.Transactions
import ninja.blacknet.util.SynchronizedHashMap

/**
 * 交易獲取器
 */
object TxFetcher {
    private val inventoryChannel: Channel<Pair<Connection, List<ByteArray>>> = Channel(Channel.UNLIMITED)
    private val requested = SynchronizedHashMap<ByteArray, Long>()

    init {
        Runtime.rotate(::implementation)
        Runtime.rotate(::watchdog)
    }

    fun offer(connection: Connection, list: List<ByteArray>) {
        inventoryChannel.offer(Pair(connection, list))
    }

    suspend fun fetched(hash: ByteArray): Boolean {
        return requested.remove(hash) != null
    }

    private suspend fun implementation() {
        val (connection, inventory) = inventoryChannel.receive()

        val request = ArrayList<ByteArray>(inventory.size)
        val currTime = currentTimeMillis()

        for (hash in inventory) {
            if (requested.containsKey(hash)) {
                continue
            }

            if (TxPool.isInteresting(hash)) {
                requested.put(hash, currTime)
                request.add(hash)
            }

            if (request.size == Transactions.MAX) {
                sendRequest(connection, request)
                request.clear()
            }
        }

        if (request.size != 0) {
            sendRequest(connection, request)
        }
    }

    private fun sendRequest(connection: Connection, request: ArrayList<ByteArray>) {
        connection.sendPacket(PacketType.GetTransactions, GetTransactions(request))
    }

    /**
     * 看門狗計時器
     */
    private suspend fun watchdog() {
        delay(Node.NETWORK_TIMEOUT)

        val currTime = currentTimeMillis()
        val timeouted = requested.filterToKeyList { _, time -> currTime > time + Node.NETWORK_TIMEOUT }
        requested.removeAll(timeouted)
    }
}
