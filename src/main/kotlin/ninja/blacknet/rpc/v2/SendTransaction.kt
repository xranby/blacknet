/*
 * Copyright (c) 2018-2020 Pavel Vasin
 * Copyright (c) 2019 Blacknet Team
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.rpc.v2

import io.ktor.routing.Route
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import ninja.blacknet.core.Accepted
import ninja.blacknet.core.Transaction
import ninja.blacknet.crypto.Ed25519
import ninja.blacknet.crypto.HashSerializer
import ninja.blacknet.crypto.PaymentId
import ninja.blacknet.crypto.PrivateKeySerializer
import ninja.blacknet.crypto.PublicKeySerializer
import ninja.blacknet.db.WalletDB
import ninja.blacknet.network.Node
import ninja.blacknet.rpc.RPCServer
import ninja.blacknet.rpc.requests.*
import ninja.blacknet.serialization.bbf.binaryFormat
import ninja.blacknet.serialization.ByteArraySerializer
import ninja.blacknet.transaction.*

fun Route.sendTransaction() {
    @Serializable
    class TransferRequest(
            @SerialName("mnemonic")
            @Serializable(with = PrivateKeySerializer::class)
            val privateKey: ByteArray,
            val fee: Long,
            val amount: Long,
            @Serializable(with = PublicKeySerializer::class)
            val to: ByteArray,
            val encrypted: Byte? = null,
            val message: String? = null,
            @Serializable(with = HashSerializer::class)
            val referenceChain: ByteArray? = null
    ) : Request {
        override suspend fun handle(): TextContent = RPCServer.txMutex.withLock {
            val message = PaymentId.create(message, encrypted, privateKey, to) ?: return respondError("Failed to create payment id")
            val from = Ed25519.toPublicKey(privateKey)
            val seq = WalletDB.getSequence(from)
            val data = binaryFormat.encodeToByteArray(Transfer.serializer(), Transfer(amount, to, message))
            val tx = Transaction.create(from, seq, referenceChain ?: WalletDB.referenceChain(), fee, TxType.Transfer.type, data)
            val (hash, bytes) = tx.sign(privateKey)

            val status = Node.broadcastTx(hash, bytes)
            return if (status == Accepted)
                respondText(HashSerializer.encode(hash))
            else
                respondError("Transaction rejected: $status")
        }
    }

    post(TransferRequest.serializer(), "/api/v2/transfer")

    @Serializable
    class BurnRequest(
            @SerialName("mnemonic")
            @Serializable(with = PrivateKeySerializer::class)
            val privateKey: ByteArray,
            val fee: Long,
            val amount: Long,
            @Serializable(with = ByteArraySerializer::class)
            val message: ByteArray,
            @Serializable(with = HashSerializer::class)
            val referenceChain: ByteArray? = null
    ) : Request {
        override suspend fun handle(): TextContent = RPCServer.txMutex.withLock {
            val from = Ed25519.toPublicKey(privateKey)
            val seq = WalletDB.getSequence(from)
            val data = binaryFormat.encodeToByteArray(Burn.serializer(), Burn(amount, message))
            val tx = Transaction.create(from, seq, referenceChain ?: WalletDB.referenceChain(), fee, TxType.Burn.type, data)
            val (hash, bytes) = tx.sign(privateKey)

            val status = Node.broadcastTx(hash, bytes)
            return if (status == Accepted)
                respondText(HashSerializer.encode(hash))
            else
                respondError("Transaction rejected: $status")
        }
    }

    post(BurnRequest.serializer(), "/api/v2/burn")

    @Serializable
    class LeaseRequest(
            @SerialName("mnemonic")
            @Serializable(with = PrivateKeySerializer::class)
            val privateKey: ByteArray,
            val fee: Long,
            val amount: Long,
            @Serializable(with = PublicKeySerializer::class)
            val to: ByteArray,
            @Serializable(with = HashSerializer::class)
            val referenceChain: ByteArray? = null
    ) : Request {
        override suspend fun handle(): TextContent = RPCServer.txMutex.withLock {
            val from = Ed25519.toPublicKey(privateKey)
            val seq = WalletDB.getSequence(from)
            val data = binaryFormat.encodeToByteArray(Lease.serializer(), Lease(amount, to))
            val tx = Transaction.create(from, seq, referenceChain ?: WalletDB.referenceChain(), fee, TxType.Lease.type, data)
            val (hash, bytes) = tx.sign(privateKey)

            val status = Node.broadcastTx(hash, bytes)
            return if (status == Accepted)
                respondText(HashSerializer.encode(hash))
            else
                respondError("Transaction rejected: $status")
        }
    }

    post(LeaseRequest.serializer(), "/api/v2/lease")

    @Serializable
    class CancelLeaseRequest(
            @SerialName("mnemonic")
            @Serializable(with = PrivateKeySerializer::class)
            val privateKey: ByteArray,
            val fee: Long,
            val amount: Long,
            @Serializable(with = PublicKeySerializer::class)
            val to: ByteArray,
            val height: Int,
            @Serializable(with = HashSerializer::class)
            val referenceChain: ByteArray? = null
    ) : Request {
        override suspend fun handle(): TextContent = RPCServer.txMutex.withLock {
            val from = Ed25519.toPublicKey(privateKey)
            val seq = WalletDB.getSequence(from)
            val data = binaryFormat.encodeToByteArray(CancelLease.serializer(), CancelLease(amount, to, height))
            val tx = Transaction.create(from, seq, referenceChain ?: WalletDB.referenceChain(), fee, TxType.CancelLease.type, data)
            val (hash, bytes) = tx.sign(privateKey)

            val status = Node.broadcastTx(hash, bytes)
            return if (status == Accepted)
                respondText(HashSerializer.encode(hash))
            else
                respondError("Transaction rejected: $status")
        }
    }

    post(CancelLeaseRequest.serializer(), "/api/v2/cancellease")

    @Serializable
    class WithdrawFromLeaseRequest(
            @SerialName("mnemonic")
            @Serializable(with = PrivateKeySerializer::class)
            val privateKey: ByteArray,
            val fee: Long,
            val withdraw: Long,
            val amount: Long,
            @Serializable(with = PublicKeySerializer::class)
            val to: ByteArray,
            val height: Int,
            @Serializable(with = HashSerializer::class)
            val referenceChain: ByteArray? = null
    ) : Request {
        override suspend fun handle(): TextContent = RPCServer.txMutex.withLock {
            val from = Ed25519.toPublicKey(privateKey)
            val seq = WalletDB.getSequence(from)
            val data = binaryFormat.encodeToByteArray(WithdrawFromLease.serializer(), WithdrawFromLease(withdraw, amount, to, height))
            val tx = Transaction.create(from, seq, referenceChain ?: WalletDB.referenceChain(), fee, TxType.WithdrawFromLease.type, data)
            val (hash, bytes) = tx.sign(privateKey)

            val status = Node.broadcastTx(hash, bytes)
            return if (status == Accepted)
                respondText(HashSerializer.encode(hash))
            else
                respondError("Transaction rejected: $status")
        }
    }

    post(WithdrawFromLeaseRequest.serializer(), "/api/v2/withdrawfromlease")

    @Serializable
    class SendRawTransaction(
            @SerialName("hex")
            @Serializable(with = ByteArraySerializer::class)
            val bytes: ByteArray
    ) : Request {
        override suspend fun handle(): TextContent = RPCServer.txMutex.withLock {
            val hash = Transaction.hash(bytes)

            val status = Node.broadcastTx(hash, bytes)
            return if (status == Accepted)
                respondText(HashSerializer.encode(hash))
            else
                respondError("Transaction rejected: $status")
        }
    }

    get(SendRawTransaction.serializer(), "/api/v2/sendrawtransaction/{hex}/")
}
