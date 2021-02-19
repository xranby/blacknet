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
import kotlin.math.min
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import ninja.blacknet.core.AccountState
import ninja.blacknet.core.Transaction
import ninja.blacknet.crypto.*
import ninja.blacknet.db.BlockDB
import ninja.blacknet.db.LedgerDB
import ninja.blacknet.db.WalletDB
import ninja.blacknet.rpc.requests.*
import ninja.blacknet.rpc.v1.AddressInfo
import ninja.blacknet.rpc.v1.NewMnemonicInfo
import ninja.blacknet.rpc.v1.toHex
import ninja.blacknet.transaction.TxType
import ninja.blacknet.serialization.bbf.binaryFormat
import ninja.blacknet.util.HashMap
import ninja.blacknet.util.HashMapSerializer

fun Route.wallet() {
    @Serializable
    class GenerateAccount(
            val wordlist: String = "english"
    ) : Request {
        override suspend fun handle(): TextContent {
            val wordlist = Wordlists.get(wordlist)

            return respondJson(NewMnemonicInfo.serializer(), NewMnemonicInfo.new(wordlist))
        }
    }

    //get(GenerateAccount.serializer(), "/api/v2/generateaccount")
    get(GenerateAccount.serializer(), "/api/v2/generateaccount/{wordlist?}")

    @Serializable
    class Address(
            val address: String
    ) : Request {
        override suspend fun handle(): TextContent {
            val info = AddressInfo.fromString(address)

            return respondJson(AddressInfo.serializer(), info)
        }
    }

    get(Address.serializer(), "/api/v2/address")
    get(Address.serializer(), "/api/v2/address/{address}")

    @Serializable
    class Mnemonic(
            val mnemonic: String
    ) : Request {
        override suspend fun handle(): TextContent {
            val info = MnemonicInfo.fromString(mnemonic)

            return respondJson(MnemonicInfo.serializer(), info)
        }
    }

    post(Mnemonic.serializer(), "/api/v2/mnemonic")

    @Serializable
    class DecryptPaymentId(
            @SerialName("mnemonic")
            @Serializable(with = PrivateKeySerializer::class)
            val privateKey: ByteArray,
            @Serializable(with = PublicKeySerializer::class)
            val from: ByteArray,
            val message: String
    ) : Request {
        override suspend fun handle(): TextContent {
            val decrypted = PaymentId.decrypt(privateKey, from, message)

            return if (decrypted != null)
                respondText(decrypted)
            else
                respondError("Decryption failed")
        }
    }

    post(DecryptPaymentId.serializer(), "/api/v2/decryptpaymentid")
    post(DecryptPaymentId.serializer(), "/api/v2/decryptmessage")

    @Serializable
    class SignMessage(
            @SerialName("mnemonic")
            @Serializable(with = PrivateKeySerializer::class)
            val privateKey: ByteArray,
            val message: String
    ) : Request {
        override suspend fun handle(): TextContent {
            val signature = Message.sign(privateKey, message)

            return respondText(SignatureSerializer.encode(signature))
        }
    }

    post(SignMessage.serializer(), "/api/v2/signmessage")

    @Serializable
    class VerifyMessage(
            @Serializable(with = PublicKeySerializer::class)
            val from: ByteArray,
            @Serializable(with = SignatureSerializer::class)
            val signature: ByteArray,
            val message: String
    ) : Request {
        override suspend fun handle(): TextContent {
            val result = Message.verify(from, signature, message)

            return respondText(result.toString())
        }
    }

    get(VerifyMessage.serializer(), "/api/v2/verifymessage")
    get(VerifyMessage.serializer(), "/api/v2/verifymessage/{from}/{signature}/{message}")

    @Serializable
    class Transactions(
            @SerialName("address")
            @Serializable(with = PublicKeySerializer::class)
            val publicKey: ByteArray
    ) : Request {
        override suspend fun handle(): TextContent = WalletDB.mutex.withLock {
            val wallet = WalletDB.getWalletImpl(publicKey)
            val transactions = HashMap<String, TransactionDataInfo>(expectedSize = wallet.transactions.size)
            wallet.transactions.forEach { (hash, txData) ->
                transactions.put(HashSerializer.encode(hash), TransactionDataInfo(txData))
            }

            return respondJson(HashMapSerializer(String.serializer(), TransactionDataInfo.serializer()), transactions)
        }
    }

    //get(Transactions.serializer(), "/api/v2/wallet/transactions")
    //get(Transactions.serializer(), "/api/v2/wallet/transactions/{address}")
    get(Transactions.serializer(), "/api/v2/wallet/{address}/transactions")

    @Serializable
    class OutLeases(
            @SerialName("address")
            @Serializable(with = PublicKeySerializer::class)
            val publicKey: ByteArray
    ) : Request {
        override suspend fun handle(): TextContent = WalletDB.mutex.withLock {
            val wallet = WalletDB.getWalletImpl(publicKey)

            return respondJson(ListSerializer(AccountState.Lease.serializer()), wallet.outLeases)
        }
    }

    //get(OutLeases.serializer(), "/api/v2/wallet/outleases")
    //get(OutLeases.serializer(), "/api/v2/wallet/outleases/{address}")
    get(OutLeases.serializer(), "/api/v2/wallet/{address}/outleases")

    @Serializable
    class Sequence(
            @SerialName("address")
            @Serializable(with = PublicKeySerializer::class)
            val publicKey: ByteArray
    ) : Request {
        override suspend fun handle(): TextContent {
            return respondText(WalletDB.getSequence(publicKey).toString())
        }
    }

    //get(Sequence.serializer(), "/api/v2/wallet/sequence")
    //get(Sequence.serializer(), "/api/v2/wallet/sequence/{address}")
    get(Sequence.serializer(), "/api/v2/wallet/{address}/sequence")

    @Serializable
    class TransactionRequest(
            @SerialName("address")
            @Serializable(with = PublicKeySerializer::class)
            val publicKey: ByteArray,
            @Serializable(with = HashSerializer::class)
            val hash: ByteArray,
            val raw: Boolean = false
    ) : Request {
        override suspend fun handle(): TextContent = WalletDB.mutex.withLock {
            val wallet = WalletDB.getWalletImpl(publicKey)
            val txData = wallet.transactions.get(hash)
            return if (txData != null) {
                val bytes = WalletDB.getTransactionImpl(hash)!!
                if (raw) {
                    respondText(@Suppress("DEPRECATION") bytes.toHex())
                } else {
                    val tx = binaryFormat.decodeFromByteArray(Transaction.serializer(), bytes)
                    respondJson(TransactionInfo.serializer(), TransactionInfo(tx, hash, bytes.size, txData.types))
                }
            } else {
                respondError("Transaction not found")
            }
        }
    }

    //get(TransactionRequest.serializer(), "/api/v2/wallet/transaction")
    //get(TransactionRequest.serializer(), "/api/v2/wallet/transaction/{address}/{hash}/{raw?}")
    get(TransactionRequest.serializer(), "/api/v2/wallet/{address}/transaction/{hash}/{raw?}")

    @Serializable
    class Confirmations(
            @SerialName("address")
            @Serializable(with = PublicKeySerializer::class)
            val publicKey: ByteArray,
            @Serializable(with = HashSerializer::class)
            val hash: ByteArray
    ) : Request {
        override suspend fun handle(): TextContent {
            val result = WalletDB.getConfirmations(publicKey, hash)
            return if (result != null)
                respondText(result.toString())
            else
                respondError("Transaction not found")
        }
    }

    //get(Confirmations.serializer(), "/api/v2/wallet/confirmations")
    //get(Confirmations.serializer(), "/api/v2/wallet/confirmations/{address}/{hash}")
    get(Confirmations.serializer(), "/api/v2/wallet/{address}/confirmations/{hash}")

    @Serializable
    class ReferenceChain(
            @SerialName("address")
            @Serializable(with = PublicKeySerializer::class)
            val publicKey: ByteArray
    ) : Request {
        override suspend fun handle(): TextContent {
            val result = WalletDB.referenceChain()
            return respondText(HashSerializer.encode(result))
        }
    }

    //get(ReferenceChain.serializer(), "/api/v2/wallet/referencechain")
    //get(ReferenceChain.serializer(), "/api/v2/wallet/referencechain/{address}")
    get(ReferenceChain.serializer(), "/api/v2/wallet/{address}/referencechain")

    @Serializable
    class TxCount(
            @SerialName("address")
            @Serializable(with = PublicKeySerializer::class)
            val publicKey: ByteArray
    ) : Request {
        override suspend fun handle(): TextContent = WalletDB.mutex.withLock {
            val wallet = WalletDB.getWalletImpl(publicKey)
            val count = wallet.transactions.size
            return respondText(count.toString())
        }
    }

    //get(TxCount.serializer(), "/api/v2/wallet/txcount")
    //get(TxCount.serializer(), "/api/v2/wallet/txcount/{address}")
    get(TxCount.serializer(), "/api/v2/wallet/{address}/txcount")

    @Serializable
    class ListTransactions(
            @SerialName("address")
            @Serializable(with = PublicKeySerializer::class)
            val publicKey: ByteArray,
            val offset: Int = 0,
            val max: Int = 100,
            val type: Int? = null
    ) : Request {
        override suspend fun handle(): TextContent = WalletDB.mutex.withLock {
            val wallet = WalletDB.getWalletImpl(publicKey)
            BlockDB.mutex.withLock {
                val size = wallet.transactions.size
                if (offset < 0 || offset > size)
                    return respondError("Invalid offset")
                if (max < 0 || max > Int.MAX_VALUE)
                    return respondError("Invalid max")
                val toIndex = min(offset + max, size)
                val transactions = ArrayList<WalletTransactionInfo>(min(max, size))
                val state = LedgerDB.state()
                val list = wallet.transactions.entries.sortedByDescending { (_, txData) -> txData.time }
                if (type == null) {
                    for (index in offset until toIndex) {
                        val (hash, txData) = list[index]
                        val bytes = WalletDB.getTransactionImpl(hash)!!
                        val tx = binaryFormat.decodeFromByteArray(Transaction.serializer(), bytes)
                        transactions.add(WalletTransactionInfo(
                                TransactionInfo(tx, hash, bytes.size, txData.types),
                                txData.confirmationsImpl(state),
                                txData.time
                        ))
                    }
                } else {
                    require(offset >= 0) { "偏移不能为负数" }
                    var offsetNumber = offset
                    val type = type.toUByte().toByte().also { if (it != TxType.Generated.type) TxType.getSerializer(it) /* 请校验请求引数 */ }
                    for (index in 0 until list.size) {
                        val (hash, txData) = list[index]
                        val filter = txData.types.filter { it.type == type }
                        if (filter.size == 0)
                            continue
                        if (offsetNumber != 0) {
                            offsetNumber -= 1
                            continue
                        }
                        val bytes = WalletDB.getTransactionImpl(hash)!!
                        val tx = binaryFormat.decodeFromByteArray(Transaction.serializer(), bytes)
                        transactions.add(WalletTransactionInfo(
                            TransactionInfo(tx, hash, bytes.size, filter),
                            txData.confirmationsImpl(state),
                            txData.time
                        ))
                        if (transactions.size == max)
                            break
                    }
                }
                return respondJson(ListSerializer(WalletTransactionInfo.serializer()), transactions)
            }
        }
    }

    //get(ListTransactions.serializer(), "/api/v2/wallet/listtransactions")
    //get(ListTransactions.serializer(), "/api/v2/wallet/listtransactions/{address}/{offset?}/{max?}/{type?}")
    get(ListTransactions.serializer(), "/api/v2/wallet/{address}/listtransactions/{offset?}/{max?}/{type?}")

    @Serializable
    class ListSinceBlockInfo(
            val transactions: List<WalletTransactionInfo>,
            @Serializable(with = HashSerializer::class)
            val lastBlockHash: ByteArray
    )

    @Serializable
    class ListSinceBlock(
            @SerialName("address")
            @Serializable(with = PublicKeySerializer::class)
            val publicKey: ByteArray,
            @Serializable(with = HashSerializer::class)
            val hash: ByteArray = HashSerializer.ZERO
    ) : Request {
        override suspend fun handle(): TextContent = WalletDB.mutex.withLock {
            val wallet = WalletDB.getWalletImpl(publicKey)
            BlockDB.mutex.withLock {
                val height = LedgerDB.getChainIndex(hash)?.height ?: return respondError("Block not found")
                val state = LedgerDB.state()
                if (height >= state.height - PoS.MATURITY)
                    return respondError("Block not finalized")
                val transactions = ArrayList<WalletTransactionInfo>()
                wallet.transactions.forEach { (hash, txData) ->
                    if (txData.height != 0 && height >= txData.height) {
                        val bytes = WalletDB.getTransactionImpl(hash)!!
                        val tx = binaryFormat.decodeFromByteArray(Transaction.serializer(), bytes)
                        transactions.add(WalletTransactionInfo(
                                TransactionInfo(tx, hash, bytes.size, txData.types),
                                txData.confirmationsImpl(state),
                                txData.time
                        ))
                    }
                }
                return respondJson(ListSinceBlockInfo.serializer(), ListSinceBlockInfo(transactions, state.rollingCheckpoint))
            }
        }
    }

    //get(ListSinceBlock.serializer(), "/api/v2/wallet/listsinceblock")
    //get(ListSinceBlock.serializer(), "/api/v2/wallet/listsinceblock/{address}/{hash?}")
    get(ListSinceBlock.serializer(), "/api/v2/wallet/{address}/listsinceblock/{hash?}")
}
