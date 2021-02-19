/*
 * Copyright (c) 2018-2020 Pavel Vasin
 * Copyright (c) 2019 Blacknet Team
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

@file:Suppress("DEPRECATION")

package ninja.blacknet.rpc.v1

import io.ktor.application.call
import io.ktor.http.HttpStatusCode
import io.ktor.http.cio.websocket.CloseReason
import io.ktor.http.cio.websocket.Frame
import io.ktor.http.cio.websocket.close
import io.ktor.http.cio.websocket.readText
import io.ktor.response.respond
import io.ktor.routing.Route
import io.ktor.routing.get
import io.ktor.routing.post
import io.ktor.websocket.webSocket
import kotlinx.coroutines.channels.ClosedReceiveChannelException
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.builtins.*
import ninja.blacknet.rpc.*
import ninja.blacknet.core.*
import ninja.blacknet.crypto.*
import ninja.blacknet.dataDir
import ninja.blacknet.db.*
import ninja.blacknet.network.Network
import ninja.blacknet.network.Node
import ninja.blacknet.serialization.bbf.*
import ninja.blacknet.transaction.*
import ninja.blacknet.util.*
import java.io.File
import kotlin.math.abs

fun Route.APIV1() {
    webSocket("/api/v1/notify/block") {
        try {
            RPCServerV1.blockNotifyV0.add(outgoing)
            while (true) {
                incoming.receive()
            }
        } catch (e: ClosedReceiveChannelException) {
        } finally {
            RPCServerV1.blockNotifyV0.remove(outgoing)
        }
    }

    webSocket("/api/v2/notify/block") {
        try {
            RPCServerV1.blockNotifyV1.add(outgoing)
            while (true) {
                incoming.receive()
            }
        } catch (e: ClosedReceiveChannelException) {
        } finally {
            RPCServerV1.blockNotifyV1.remove(outgoing)
        }
    }

    webSocket("/api/v1/notify/transaction") {
        try {
            while (true) {
                val string = (incoming.receive() as Frame.Text).readText()
                @Suppress("USELESS_ELVIS")
                val publicKey = Address.decode(string) ?: return@webSocket this.close(CloseReason(CloseReason.Codes.PROTOCOL_ERROR, "invalid account"))

                RPCServerV1.walletNotifyV1.mutex.withLock<Unit> {
                    val keys = RPCServerV1.walletNotifyV1.map.get(outgoing)
                    if (keys == null) {
                        @Suppress("NAME_SHADOWING")
                        val keys = HashSet<ByteArray>()
                        keys.add(publicKey)
                        RPCServerV1.walletNotifyV1.map.put(outgoing, keys)
                    } else {
                        keys.add(publicKey)
                    }
                }
            }
        } catch (e: ClosedReceiveChannelException) {
        } finally {
            RPCServerV1.walletNotifyV1.remove(outgoing)
        }
    }

    get("/api/v1/peerinfo") {
        call.respond(Json.stringify(ListSerializer(PeerInfoV1.serializer()), PeerInfoV1.getAll()))
    }

    get("/api/v1/nodeinfo") {
        call.respond(Json.stringify(NodeInfo.serializer(), NodeInfo.get()))
    }

    get("/api/v1/peerdb") {
        call.respond(Json.stringify(PeerDBInfo.serializer(), PeerDBInfo.get()))
    }

    get("/api/v1/peerdb/networkstat") {
        call.respond(Json.stringify(PeerDBInfo.serializer(), PeerDBInfo.get(true)))
    }

    get("/api/v1/leveldb/stats") {
        call.respond(LevelDB.getProperty("leveldb.stats") ?: "Not implemented")
    }

    get("/api/v1/blockdb/get/{hash}/{txdetail?}") {
        val hash = call.parameters["hash"]?.let { HashSerializer.decode(it) } ?: return@get call.respond(HttpStatusCode.BadRequest, "invalid hash")
        val txdetail = call.parameters["txdetail"]?.toBoolean() ?: false

        val result = BlockInfoV1.get(hash, txdetail)
        if (result != null)
            call.respond(Json.stringify(BlockInfoV1.serializer(), result))
        else
            call.respond(HttpStatusCode.NotFound, "block not found")
    }

    get("/api/v2/blockdb/get/{hash}/{txdetail?}") {
        val hash = call.parameters["hash"]?.let { HashSerializer.decode(it) } ?: return@get call.respond(HttpStatusCode.BadRequest, "invalid hash")
        val txdetail = call.parameters["txdetail"]?.toBoolean() ?: false

        val result = BlockDB.block(hash)
        if (result != null)
            call.respond(Json.stringify(BlockInfoV2.serializer(), BlockInfoV2(result.first, hash, result.second, txdetail)))
        else
            call.respond(HttpStatusCode.NotFound, "block not found")
    }

    get("/api/v1/blockdb/getblockhash/{height}") {
        val height = call.parameters["height"]?.toIntOrNull() ?: return@get call.respond(HttpStatusCode.BadRequest, "invalid height")

        BlockDB.mutex.withLock {
            val state = LedgerDB.state()
            if (height < 0 || height > state.height)
                return@get call.respond(HttpStatusCode.NotFound, "block not found")
            else if (height == 0)
                return@get call.respond(HashSerializer.encode(HashSerializer.ZERO))
            else if (height == state.height)
                return@get call.respond(HashSerializer.encode(state.blockHash))

            if (RPCServer.lastIndex != null && RPCServer.lastIndex!!.second.height == height)
                return@get call.respond(HashSerializer.encode(RPCServer.lastIndex!!.first))

            var hash: ByteArray
            var index: ChainIndex
            if (height < state.height / 2) {
                hash = HashSerializer.ZERO
                index = LedgerDB.getChainIndex(hash)!!
            } else {
                hash = state.blockHash
                index = LedgerDB.getChainIndex(hash)!!
            }
            if (RPCServer.lastIndex != null && abs(height - index.height) > abs(height - RPCServer.lastIndex!!.second.height))
                index = RPCServer.lastIndex!!.second
            while (index.height > height) {
                hash = index.previous
                index = LedgerDB.getChainIndex(hash)!!
            }
            while (index.height < height) {
                hash = index.next
                index = LedgerDB.getChainIndex(hash)!!
            }
            if (index.height < state.height - PoS.MATURITY + 1)
                RPCServer.lastIndex = Pair(hash, index)
            call.respond(HashSerializer.encode(hash))
        }
    }

    get("/api/v1/blockdb/getblockindex/{hash}/") {
        val hash = call.parameters["hash"]?.let { HashSerializer.decode(it) } ?: return@get call.respond(HttpStatusCode.BadRequest, "invalid hash")

        val result = LedgerDB.getChainIndex(hash)
        if (result != null)
            call.respond(Json.stringify(ChainIndex.serializer(), result))
        else
            call.respond(HttpStatusCode.NotFound, "block not found")
    }

    get("/api/v1/blockdb/makebootstrap") {
        val checkpoint = LedgerDB.state().rollingCheckpoint
        if (checkpoint.contentEquals(HashSerializer.ZERO))
            return@get call.respond(HttpStatusCode.BadRequest, "not synchronized")

        val file = File(dataDir, "bootstrap.dat.new")
        val stream = file.outputStream().buffered().data()

        var hash = HashSerializer.ZERO
        var index = LedgerDB.getChainIndex(hash)!!
        do {
            hash = index.next
            index = LedgerDB.getChainIndex(hash)!!
            val bytes = BlockDB.getImpl(hash)!!
            stream.writeInt(bytes.size)
            stream.write(bytes, 0, bytes.size)
        } while (!hash.contentEquals(checkpoint))

        stream.close()

        call.respond(file.absolutePath)
    }

    get("/api/v1/ledger") {
        call.respond(Json.stringify(LedgerInfo.serializer(), LedgerInfo.get()))
    }

    get("/api/v1/ledger/get/{account}/{confirmations?}") {
        val publicKey = call.parameters["account"]?.let { Address.decode(it) } ?: return@get call.respond(HttpStatusCode.BadRequest, "invalid account")
        val confirmations = call.parameters["confirmations"]?.toIntOrNull() ?: PoS.DEFAULT_CONFIRMATIONS
        val result = AccountInfoV1.get(publicKey, confirmations)
        if (result != null)
            call.respond(Json.stringify(AccountInfoV1.serializer(), result))
        else
            call.respond(HttpStatusCode.NotFound, "account not found")
    }

    get("/api/v1/ledger/check") {
        call.respond(Json.stringify(LedgerDB.Check.serializer(), LedgerDB.check()))
    }

    get("/api/v1/txpool") {
        call.respond(Json.stringify(TxPoolInfo.serializer(), TxPoolInfo.get()))
    }

    get("/api/v1/account/generate") {
        val wordlist = Wordlists.get("english")

        call.respond(Json.stringify(NewMnemonicInfo.serializer(), NewMnemonicInfo.new(wordlist)))
    }

    get("/api/v1/address/info/{address}") {
        val info = call.parameters["address"]?.let { AddressInfo.fromString(it) } ?: return@get call.respond(HttpStatusCode.BadRequest, "invalid address")

        call.respond(Json.stringify(AddressInfo.serializer(), info))
    }

    post("/api/v1/mnemonic/info/{mnemonic}") {
        val info = call.parameters["mnemonic"]?.let { NewMnemonicInfo.fromString(it) } ?: return@post call.respond(HttpStatusCode.BadRequest, "invalid mnemonic")

        call.respond(Json.stringify(NewMnemonicInfo.serializer(), info))
    }

    post("/api/v1/transfer/{mnemonic}/{fee}/{amount}/{to}/{message?}/{encrypted?}/{blockHash?}/") {
        val privateKey = call.parameters["mnemonic"]?.let { Mnemonic.fromString(it) } ?: return@post call.respond(HttpStatusCode.BadRequest, "invalid mnemonic")
        val from = Ed25519.toPublicKey(privateKey)
        val fee = call.parameters["fee"]?.toLongOrNull() ?: return@post call.respond(HttpStatusCode.BadRequest, "invalid fee")
        val amount = call.parameters["amount"]?.toLongOrNull() ?: return@post call.respond(HttpStatusCode.BadRequest, "invalid amount")
        val to = call.parameters["to"]?.let { Address.decode(it) } ?: return@post call.respond(HttpStatusCode.BadRequest, "invalid to")
        val encrypted = call.parameters["encrypted"]?.let { it.toByteOrNull() ?: return@post call.respond(HttpStatusCode.BadRequest, "invalid encrypted") }
        val message = PaymentId.create(call.parameters["message"], encrypted, privateKey, to) ?: return@post call.respond(HttpStatusCode.BadRequest, "failed to create message")
        val blockHash = call.parameters["blockHash"]?.let @Suppress("USELESS_ELVIS") { HashSerializer.decode(it) ?: return@post call.respond(HttpStatusCode.BadRequest, "invalid blockHash") }

        RPCServer.txMutex.withLock {
            @Suppress("USELESS_ELVIS")
            val seq = WalletDB.getSequence(from) ?: return@post call.respond(HttpStatusCode.BadRequest, "wallet reached sequence threshold")
            val data = binaryFormat.encodeToByteArray(Transfer.serializer(), Transfer(amount, to, message))
            val tx = Transaction.create(from, seq, blockHash
                    ?: WalletDB.referenceChain(), fee, TxType.Transfer.type, data)
            val signed = tx.sign(privateKey)

            if (Node.broadcastTx(signed.first, signed.second) == Accepted)
                call.respond(signed.first.toHex())
            else
                call.respond("Transaction rejected")
        }
    }

    post("/api/v1/burn/{mnemonic}/{fee}/{amount}/{message?}/{blockHash?}/") {
        val privateKey = call.parameters["mnemonic"]?.let { Mnemonic.fromString(it) } ?: return@post call.respond(HttpStatusCode.BadRequest, "invalid mnemonic")
        val from = Ed25519.toPublicKey(privateKey)
        val fee = call.parameters["fee"]?.toLongOrNull() ?: return@post call.respond(HttpStatusCode.BadRequest, "invalid fee")
        val amount = call.parameters["amount"]?.toLongOrNull() ?: return@post call.respond(HttpStatusCode.BadRequest, "invalid amount")
        val message = call.parameters["message"]?.let { fromHex(it) } ?: return@post call.respond(HttpStatusCode.BadRequest, "invalid message")
        val blockHash = call.parameters["blockHash"]?.let @Suppress("USELESS_ELVIS") { HashSerializer.decode(it) ?: return@post call.respond(HttpStatusCode.BadRequest, "invalid blockHash") }

        RPCServer.txMutex.withLock {
            @Suppress("USELESS_ELVIS")
            val seq = WalletDB.getSequence(from) ?: return@post call.respond(HttpStatusCode.BadRequest, "wallet reached sequence threshold")
            val data = binaryFormat.encodeToByteArray(Burn.serializer(), Burn(amount, message))
            val tx = Transaction.create(from, seq, blockHash ?: WalletDB.referenceChain(), fee, TxType.Burn.type, data)
            val signed = tx.sign(privateKey)

            if (Node.broadcastTx(signed.first, signed.second) == Accepted)
                call.respond(signed.first.toHex())
            else
                call.respond("Transaction rejected")
        }
    }

    post("/api/v1/lease/{mnemonic}/{fee}/{amount}/{to}/{blockHash?}/") {
        val privateKey = call.parameters["mnemonic"]?.let { Mnemonic.fromString(it) } ?: return@post call.respond(HttpStatusCode.BadRequest, "invalid mnemonic")
        val from = Ed25519.toPublicKey(privateKey)
        val fee = call.parameters["fee"]?.toLongOrNull() ?: return@post call.respond(HttpStatusCode.BadRequest, "invalid fee")
        val amount = call.parameters["amount"]?.toLongOrNull() ?: return@post call.respond(HttpStatusCode.BadRequest, "invalid amount")
        val to = call.parameters["to"]?.let { Address.decode(it) } ?: return@post call.respond(HttpStatusCode.BadRequest, "invalid to")
        val blockHash = call.parameters["blockHash"]?.let @Suppress("USELESS_ELVIS") { HashSerializer.decode(it) ?: return@post call.respond(HttpStatusCode.BadRequest, "invalid blockHash") }

        RPCServer.txMutex.withLock {
            @Suppress("USELESS_ELVIS")
            val seq = WalletDB.getSequence(from) ?: return@post call.respond(HttpStatusCode.BadRequest, "wallet reached sequence threshold")
            val data = binaryFormat.encodeToByteArray(Lease.serializer(), Lease(amount, to))
            val tx = Transaction.create(from, seq, blockHash ?: WalletDB.referenceChain(), fee, TxType.Lease.type, data)
            val signed = tx.sign(privateKey)

            if (Node.broadcastTx(signed.first, signed.second) == Accepted)
                call.respond(signed.first.toHex())
            else
                call.respond("Transaction rejected")
        }
    }

    post("/api/v1/cancellease/{mnemonic}/{fee}/{amount}/{to}/{height}/{blockHash?}/") {
        val privateKey = call.parameters["mnemonic"]?.let { Mnemonic.fromString(it) } ?: return@post call.respond(HttpStatusCode.BadRequest, "invalid mnemonic")
        val from = Ed25519.toPublicKey(privateKey)
        val fee = call.parameters["fee"]?.toLongOrNull() ?: return@post call.respond(HttpStatusCode.BadRequest, "invalid fee")
        val amount = call.parameters["amount"]?.toLongOrNull() ?: return@post call.respond(HttpStatusCode.BadRequest, "invalid amount")
        val to = call.parameters["to"]?.let { Address.decode(it) } ?: return@post call.respond(HttpStatusCode.BadRequest, "invalid to")
        val height = call.parameters["height"]?.toIntOrNull() ?: return@post call.respond(HttpStatusCode.BadRequest, "invalid height")
        val blockHash = call.parameters["blockHash"]?.let @Suppress("USELESS_ELVIS") { HashSerializer.decode(it) ?: return@post call.respond(HttpStatusCode.BadRequest, "invalid blockHash") }

        RPCServer.txMutex.withLock {
            @Suppress("USELESS_ELVIS")
            val seq = WalletDB.getSequence(from) ?: return@post call.respond(HttpStatusCode.BadRequest, "wallet reached sequence threshold")
            val data = binaryFormat.encodeToByteArray(CancelLease.serializer(), CancelLease(amount, to, height))
            val tx = Transaction.create(from, seq, blockHash
                    ?: WalletDB.referenceChain(), fee, TxType.CancelLease.type, data)
            val signed = tx.sign(privateKey)

            if (Node.broadcastTx(signed.first, signed.second) == Accepted)
                call.respond(signed.first.toHex())
            else
                call.respond("Transaction rejected")
        }
    }

    get("/api/v1/transaction/raw/send/{serialized}/") {
        val serialized = call.parameters["serialized"]?.let { fromHex(it) } ?: return@get call.respond(HttpStatusCode.BadRequest, "invalid serialized")
        val hash = Transaction.hash(serialized)

        RPCServer.txMutex.withLock {
            if (Node.broadcastTx(hash, serialized) == Accepted)
                call.respond(hash.toHex())
            else
                call.respond("Transaction rejected")
        }
    }

    post("/api/v1/decryptmessage/{mnemonic}/{from}/{message}") {
        val privateKey = call.parameters["mnemonic"]?.let { Mnemonic.fromString(it) } ?: return@post call.respond(HttpStatusCode.BadRequest, "invalid mnemonic")
        val publicKey = call.parameters["from"]?.let { Address.decode(it) } ?: return@post call.respond(HttpStatusCode.BadRequest, "invalid from")
        val message = call.parameters["message"] ?: return@post call.respond(HttpStatusCode.BadRequest, "invalid message")

        val decrypted = PaymentId.decrypt(privateKey, publicKey, message)
        if (decrypted != null)
            call.respond(decrypted)
        else
            call.respond(HttpStatusCode.NotFound, "Decryption failed")
    }

    post("/api/v1/signmessage/{mnemonic}/{message}") {
        val privateKey = call.parameters["mnemonic"]?.let { Mnemonic.fromString(it) } ?: return@post call.respond(HttpStatusCode.BadRequest, "invalid mnemonic")
        val message = call.parameters["message"] ?: return@post call.respond(HttpStatusCode.BadRequest, "invalid message")

        val signature = Message.sign(privateKey, message)

        call.respond(signature.toHex())
    }

    get("/api/v1/verifymessage/{account}/{signature}/{message}") {
        val publicKey = call.parameters["account"]?.let { Address.decode(it) } ?: return@get call.respond(HttpStatusCode.BadRequest, "invalid account")
        val signature = call.parameters["signature"]?.let { SignatureSerializer.decode(it) } ?: return@get call.respond(HttpStatusCode.BadRequest, "invalid signature")
        val message = call.parameters["message"] ?: return@get call.respond(HttpStatusCode.BadRequest, "invalid message")

        val result = Message.verify(publicKey, signature, message)

        call.respond(result.toString())
    }

    get("/api/v1/addpeer/{address}/{port?}/{force?}") {
        val port = call.parameters["port"]?.let { Network.parsePort(it) ?: return@get call.respond(HttpStatusCode.BadRequest, "invalid port") } ?: Node.DEFAULT_P2P_PORT
        val address = Network.parse(call.parameters["address"], port) ?: return@get call.respond(HttpStatusCode.BadRequest, "invalid address")
        val force = call.parameters["force"]?.toBoolean() ?: false

        try {
            val connection = Node.connections.find { it.remoteAddress == address }
            if (force || connection == null) {
                Node.connectTo(address)
                call.respond("Connected")
            } else {
                call.respond("Already connected on ${connection.localAddress}")
            }
        } catch (e: Throwable) {
            call.respond(e.message ?: "unknown error")
        }
    }

    get("/api/v1/disconnectpeer/{address}/{port?}/{force?}") {
        val port = call.parameters["port"]?.let { Network.parsePort(it) ?: return@get call.respond(HttpStatusCode.BadRequest, "invalid port") } ?: Node.DEFAULT_P2P_PORT
        val address = Network.parse(call.parameters["address"], port) ?: return@get call.respond(HttpStatusCode.BadRequest, "invalid address")
        @Suppress("UNUSED_VARIABLE")
        val force = call.parameters["force"]?.toBoolean() ?: false

        val connection = Node.connections.find { it.remoteAddress == address }
        if (connection != null) {
            connection.close()
            call.respond("Disconnected")
        } else {
            call.respond("Not connected to ${address}")
        }
    }

    get("/api/v1/disconnectpeerbyid/{id}/{force?}") {
        val id = call.parameters["id"]?.toLongOrNull() ?: return@get call.respond(HttpStatusCode.BadRequest, "invalid id")
        @Suppress("UNUSED_VARIABLE")
        val force = call.parameters["force"]?.toBoolean() ?: false

        val connection = Node.connections.find { it.peerId == id }
        if (connection != null) {
            connection.close()
            call.respond("Disconnected")
        } else {
            call.respond("Not connected")
        }
    }

    post("/api/v1/staker/start/{mnemonic}") {
        val privateKey = call.parameters["mnemonic"]?.let { Mnemonic.fromString(it) } ?: return@post call.respond(HttpStatusCode.BadRequest, "invalid mnemonic")

        call.respond(Staker.startStaking(privateKey).toString())
    }

    post("/api/v1/staker/stop/{mnemonic}") {
        val privateKey = call.parameters["mnemonic"]?.let { Mnemonic.fromString(it) } ?: return@post call.respond(HttpStatusCode.BadRequest, "invalid mnemonic")

        call.respond(Staker.stopStaking(privateKey).toString())
    }

    post("/api/v1/startStaking/{mnemonic}") {
        val privateKey = call.parameters["mnemonic"]?.let { Mnemonic.fromString(it) } ?: return@post call.respond(HttpStatusCode.BadRequest, "invalid mnemonic")

        call.respond(Staker.startStaking(privateKey).toString())
    }

    post("/api/v1/stopStaking/{mnemonic}") {
        val privateKey = call.parameters["mnemonic"]?.let { Mnemonic.fromString(it) } ?: return@post call.respond(HttpStatusCode.BadRequest, "invalid mnemonic")

        call.respond(Staker.stopStaking(privateKey).toString())
    }

    post("/api/v1/isStaking/{mnemonic}") {
        val privateKey = call.parameters["mnemonic"]?.let { Mnemonic.fromString(it) } ?: return@post call.respond(HttpStatusCode.BadRequest, "invalid mnemonic")

        call.respond(Staker.isStaking(privateKey).toString())
    }

    get("/api/v1/walletdb/getwallet/{address}") {
        val publicKey = call.parameters["address"]?.let { Address.decode(it) } ?: return@get call.respond(HttpStatusCode.BadRequest, "invalid address")

        WalletDB.mutex.withLock {
            call.respond(Json.stringify(WalletV1.serializer(), WalletV1(WalletDB.getWalletImpl(publicKey))))
        }
    }

    get("/api/v1/walletdb/getoutleases/{address}") {
        val publicKey = call.parameters["address"]?.let { Address.decode(it) } ?: return@get call.respond(HttpStatusCode.BadRequest, "invalid address")

        WalletDB.mutex.withLock {
            val wallet = WalletDB.getWalletImpl(publicKey)
            call.respond(Json.stringify(ListSerializer(AccountState.Lease.serializer()), wallet.outLeases))
        }
    }

    get("/api/v1/walletdb/getsequence/{address}") {
        val publicKey = call.parameters["address"]?.let { Address.decode(it) } ?: return@get call.respond(HttpStatusCode.BadRequest, "invalid address")

        call.respond(WalletDB.getSequence(publicKey).toString())
    }

    get("/api/v1/walletdb/gettransaction/{hash}/{raw?}") {
        val hash = call.parameters["hash"]?.let { HashSerializer.decode(it) } ?: return@get call.respond(HttpStatusCode.BadRequest, "invalid hash")
        val raw = call.parameters["raw"]?.toBoolean() ?: false

        val result = WalletDB.mutex.withLock {
            WalletDB.getTransactionImpl(hash)
        }
        if (result != null) {
            if (raw)
                return@get call.respond(result.toHex())

            val tx = binaryFormat.decodeFromByteArray(Transaction.serializer(), result)
            call.respond(Json.stringify(TransactionInfoV2.serializer(), TransactionInfoV2(tx, hash, result.size)))
        } else {
            call.respond(HttpStatusCode.NotFound, "transaction not found")
        }
    }

    get("/api/v1/walletdb/getconfirmations/{hash}") {
        val hash = call.parameters["hash"]?.let { HashSerializer.decode(it) } ?: return@get call.respond(HttpStatusCode.BadRequest, "invalid hash")

        val result = WalletDB.getConfirmations(hash)
        if (result != null)
            call.respond(result.toString())
        else
            call.respond(HttpStatusCode.NotFound, "transaction not found")
    }
}
