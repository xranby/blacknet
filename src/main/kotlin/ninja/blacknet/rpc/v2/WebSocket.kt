/*
 * Copyright (c) 2018-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.rpc.v2

import io.ktor.http.cio.websocket.Frame
import io.ktor.http.cio.websocket.readText
import io.ktor.routing.Route
import io.ktor.websocket.webSocket
import kotlinx.coroutines.channels.ClosedReceiveChannelException
import kotlinx.coroutines.channels.SendChannel
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import ninja.blacknet.crypto.Address
import ninja.blacknet.rpc.RPCServer
import ninja.blacknet.serialization.json.json

fun Route.webSocket() {
    webSocket("/api/v2/websocket") {
        try {
            while (true) {
                val string = (incoming.receive() as Frame.Text).readText()
                val request = json.parseToJsonElement(string).jsonObject
                val command = request.getString("command")

                if (command == "subscribe") {
                    val route = request.getString("route")

                    if (route == "block") {
                        RPCServer.blockNotify.add(outgoing)
                    } else if (route == "txpool") {
                        RPCServer.txPoolNotify.add(outgoing)
                    } else if (route == "wallet") {
                        val address = request.getString("address")
                        val publicKey = Address.decode(address)

                        RPCServer.walletNotify.mutex.withLock {
                            val subscribers = RPCServer.walletNotify.map.get(publicKey)
                            if (subscribers == null) {
                                @Suppress("NAME_SHADOWING")
                                val subscribers = ArrayList<SendChannel<Frame>>()
                                subscribers.add(outgoing)
                                RPCServer.walletNotify.map.put(publicKey, subscribers)
                            } else {
                                subscribers.add(outgoing)
                            }
                        }
                    }
                } else if (command == "unsubscribe") {
                    val route = request.getString("route")

                    if (route == "block") {
                        RPCServer.blockNotify.remove(outgoing)
                    } else if (route == "txpool") {
                        RPCServer.txPoolNotify.remove(outgoing)
                    } else if (route == "wallet") {
                        val address = request.getString("address")
                        val publicKey = Address.decode(address)

                        RPCServer.walletNotify.mutex.withLock {
                            val subscribers = RPCServer.walletNotify.map.get(publicKey)
                            if (subscribers != null) {
                                subscribers.remove(outgoing)
                                if (subscribers.isEmpty())
                                    RPCServer.walletNotify.map.remove(publicKey)
                            }
                        }
                    }
                }
            }
        } catch (e: ClosedReceiveChannelException) {
        } finally {
            RPCServer.blockNotify.remove(outgoing)
            RPCServer.txPoolNotify.remove(outgoing)
            RPCServer.walletNotify.forEach { (_, subscribers) ->
                subscribers.remove(outgoing)
            } // 移除空
        }
    }
}

private fun JsonObject.getString(key: String) = (get(key) ?: throw RuntimeException("Missing $key")).jsonPrimitive.content
