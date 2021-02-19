/*
 * Copyright (c) 2018-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.rpc.v2

import io.ktor.routing.Route
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import ninja.blacknet.codec.base.Base16
import ninja.blacknet.core.Transaction
import ninja.blacknet.core.TxPool
import ninja.blacknet.crypto.HashSerializer
import ninja.blacknet.network.Network
import ninja.blacknet.network.Node
import ninja.blacknet.network.toPort
import ninja.blacknet.rpc.requests.*
import ninja.blacknet.rpc.v1.NodeInfo
import ninja.blacknet.rpc.v1.TxPoolInfo
import ninja.blacknet.serialization.bbf.binaryFormat

fun Route.node() {
    @Serializable
    class Peers : Request {
        override suspend fun handle(): TextContent {
            return respondJson(ListSerializer(PeerInfo.serializer()), PeerInfo.getAll())
        }
    }

    get(Peers.serializer(), "/api/v2/peers")

    @Serializable
    class NodeRequest : Request {
        override suspend fun handle(): TextContent {
            return respondJson(NodeInfo.serializer(), NodeInfo.get())
        }
    }

    get(NodeRequest.serializer(), "/api/v2/node")

    @Serializable
    class TxPoolRequest : Request {
        override suspend fun handle(): TextContent {
            return respondJson(TxPoolInfo.serializer(), TxPoolInfo.get())
        }
    }

    get(TxPoolRequest.serializer(), "/api/v2/txpool")

    @Serializable
    class TxPoolTransaction(
            @Serializable(with = HashSerializer::class)
            val hash: ByteArray,
            val raw: Boolean = false
    ) : Request {
        override suspend fun handle(): TextContent {
            val result = TxPool.get(hash)
            return if (result != null) {
                if (raw)
                    return respondText(Base16.encode(result))

                val tx = binaryFormat.decodeFromByteArray(Transaction.serializer(), result)
                respondJson(TransactionInfo.serializer(), TransactionInfo(tx, hash, result.size))
            } else {
                respondError("Transaction not found")
            }
        }
    }

    get(TxPoolTransaction.serializer(), "/api/v2/txpool/transaction")
    get(TxPoolTransaction.serializer(), "/api/v2/txpool/transaction/{hash}/{raw?}")

    @Serializable
    class AddPeer(
            val port: String = Node.DEFAULT_P2P_PORT.toPort().toString(),
            val address: String,
            val force: Boolean = false
    ) : Request {
        override suspend fun handle(): TextContent {
            val port = Network.parsePort(port) ?: return respondError("Invalid port")
            val address = Network.parse(address, port) ?: return respondError("Invalid address")

            val connection = Node.connections.find { it.remoteAddress == address }
            return if (force || connection == null) {
                Node.connectTo(address)
                respondText(true.toString())
            } else {
                respondError("Already connected on ${connection.localAddress}")
            }
        }
    }

    get(AddPeer.serializer(), "/api/v2/addpeer")
    get(AddPeer.serializer(), "/api/v2/addpeer/{address}/{port?}/{force?}")

    @Serializable
    class DisconnectPeerByAddress(
            val port: String = Node.DEFAULT_P2P_PORT.toPort().toString(),
            val address: String,
            @Suppress("unused")
            val force: Boolean = false
    ) : Request {
        override suspend fun handle(): TextContent {
            val port = Network.parsePort(port) ?: return respondError("Invalid port")
            val address = Network.parse(address, port) ?: return respondError("Invalid address")

            val connection = Node.connections.find { it.remoteAddress == address }
            return if (connection != null) {
                connection.close()
                respondText(true.toString())
            } else {
                respondText(false.toString())
            }
        }
    }

    get(DisconnectPeerByAddress.serializer(), "/api/v2/disconnectpeerbyaddress")
    get(DisconnectPeerByAddress.serializer(), "/api/v2/disconnectpeerbyaddress/{address}/{port?}/{force?}")

    @Serializable
    class DisconnectPeer(
            val id: Long,
            @Suppress("unused")
            val force: Boolean = false
    ) : Request {
        override suspend fun handle(): TextContent {
            val connection = Node.connections.find { it.peerId == id }
            return if (connection != null) {
                connection.close()
                respondText(true.toString())
            } else {
                respondText(false.toString())
            }
        }
    }

    get(DisconnectPeer.serializer(), "/api/v2/disconnectpeer")
    get(DisconnectPeer.serializer(), "/api/v2/disconnectpeer/{id}/{force?}")
}
