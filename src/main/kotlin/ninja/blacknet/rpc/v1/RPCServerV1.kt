/*
 * Copyright (c) 2018-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.rpc.v1

import io.ktor.application.Application
import io.ktor.application.call
import io.ktor.application.install
import io.ktor.features.DefaultHeaders
import io.ktor.features.StatusPages
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.cio.websocket.Frame
import io.ktor.response.respond
import io.ktor.routing.Routing
import io.ktor.websocket.WebSockets
import kotlinx.coroutines.channels.SendChannel
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import mu.KotlinLogging
import ninja.blacknet.Runtime
import ninja.blacknet.Version
import ninja.blacknet.core.Block
import ninja.blacknet.core.ChainIndex
import ninja.blacknet.core.Transaction
import ninja.blacknet.crypto.HashSerializer
import ninja.blacknet.db.WalletDB
import ninja.blacknet.logging.debug
import ninja.blacknet.logging.debugMessage
import ninja.blacknet.logging.error
import ninja.blacknet.rpc.requests.Requests
import ninja.blacknet.serialization.json.json
import ninja.blacknet.serialization.statusMessage
import ninja.blacknet.util.HashSet
import ninja.blacknet.util.SynchronizedArrayList
import ninja.blacknet.util.SynchronizedHashMap
import ninja.blacknet.util.SynchronizedHashSet

private val logger = KotlinLogging.logger {}

object RPCServerV1 {
    internal val blockNotifyV0 = SynchronizedArrayList<SendChannel<Frame>>()
    internal val blockNotifyV1 = SynchronizedArrayList<SendChannel<Frame>>()
    internal val walletNotifyV1 = SynchronizedHashMap<SendChannel<Frame>, HashSet<ByteArray>>()

    suspend fun blockNotify(block: Block, hash: ByteArray, height: Int, size: Int) {
        blockNotifyV0.forEach {
            Runtime.launch {
                try {
                    it.send(Frame.Text(HashSerializer.encode(hash)))
                } finally {
                }
            }
        }

        blockNotifyV1.mutex.withLock {
            if (blockNotifyV1.list.isNotEmpty()) {
                val notification = BlockNotificationV1(block, hash, height, size)
                val message = json.encodeToString(BlockNotificationV1.serializer(), notification)
                blockNotifyV1.list.forEach {
                    Runtime.launch {
                        try {
                            it.send(Frame.Text(message))
                        } finally {
                        }
                    }
                }
            }
        }
    }

    suspend fun walletNotify(tx: Transaction, hash: ByteArray, time: Long, size: Int, publicKey: ByteArray, filter: List<WalletDB.TransactionDataType>) {
        walletNotifyV1.mutex.withLock {
            if (walletNotifyV1.map.isNotEmpty()) {
                val notification = TransactionNotificationV2(tx, hash, time, size)
                val message = json.encodeToString(TransactionNotificationV2.serializer(), notification)
                walletNotifyV1.map.forEach {
                    if (it.value.contains(publicKey)) {
                        Runtime.launch {
                            try {
                                it.key.send(Frame.Text(message))
                            } finally {
                            }
                        }
                    }
                }
            }
        }
    }
}
