/*
 * Copyright (c) 2019-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.db

import java.io.File
import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.Serializable
import kotlinx.serialization.Serializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonEncoder
import mu.KotlinLogging
import ninja.blacknet.Config
import ninja.blacknet.Runtime
import ninja.blacknet.contract.HashTimeLockContractIdSerializer
import ninja.blacknet.contract.MultiSignatureLockContractIdSerializer
import ninja.blacknet.core.*
import ninja.blacknet.crypto.*
import ninja.blacknet.dataDir
import ninja.blacknet.network.Node
import ninja.blacknet.network.packet.UnfilteredInvList
import ninja.blacknet.rpc.RPCServer
import ninja.blacknet.serialization.*
import ninja.blacknet.serialization.bbf.BinaryDecoder
import ninja.blacknet.serialization.bbf.BinaryEncoder
import ninja.blacknet.serialization.bbf.binaryFormat
import ninja.blacknet.transaction.*
import ninja.blacknet.util.*

private val logger = KotlinLogging.logger {}

object WalletDB {
    private const val VERSION = 8
    internal val mutex = Mutex()
    private val KEYS_KEY = DBKey(64, 0)
    private val TX_KEY = DBKey(65, HashSerializer.SIZE_BYTES)
    private val VERSION_KEY = DBKey(66, 0)
    private val WALLET_KEY = DBKey(67, PublicKeySerializer.SIZE_BYTES)
    private val wallets = HashMap<ByteArray, Wallet>()

    private fun setVersion(batch: LevelDB.WriteBatch) {
        val versionBytes = binaryFormat.encodeToByteArray(VarIntSerializer, VERSION)
        batch.put(VERSION_KEY, versionBytes)
    }

    init {
        val keysBytes = LevelDB.get(KEYS_KEY)
        val versionBytes = LevelDB.get(VERSION_KEY)

        val version = if (versionBytes != null) {
            binaryFormat.decodeFromByteArray(VarIntSerializer, versionBytes)
        } else {
            1
        }

        if (version == VERSION) {
            if (keysBytes != null) {
                var txns = 0
                val decoder = BinaryDecoder(keysBytes)
                for (i in 0 until keysBytes.size step PublicKeySerializer.SIZE_BYTES) {
                    val publicKey = decoder.decodeFixedByteArray(PublicKeySerializer.SIZE_BYTES)
                    val walletBytes = LevelDB.get(WALLET_KEY, publicKey)!!
                    val wallet = binaryFormat.decodeFromByteArray(Wallet.serializer(), walletBytes)
                    txns += wallet.transactions.size
                    wallets.put(publicKey, wallet)
                }
                if (wallets.size == 1)
                    logger.info("Loaded wallet with $txns transactions")
                else
                    logger.info("Loaded ${wallets.size} wallets with $txns transactions")
            }
        } else if (version in 1 until VERSION) {
            val batch = LevelDB.createWriteBatch()
            if (keysBytes != null) {
                clear(batch)
            }
            setVersion(batch)
            batch.write()
        } else {
            throw RuntimeException("Unknown database version $version")
        }

        Runtime.rotate(::announcer)
    }

    private suspend fun announcer() {
        val allUnconfirmed = ArrayList<ArrayList<Triple<ByteArray, ByteArray, Int>>>()

        mutex.withLock {
            wallets.forEach { (_, wallet) ->
                val unconfirmed = ArrayList<Triple<ByteArray, ByteArray, Int>>()

                wallet.transactions.forEach { (hash, txData) ->
                    if (txData.height == 0 && txData.types[0].type != TxType.Generated.type) {
                        val bytes = getTransactionImpl(hash)!!
                        val tx = binaryFormat.decodeFromByteArray(Transaction.serializer(), bytes)
                        unconfirmed.add(Triple(hash, bytes, tx.seq))
                    }
                }

                if (unconfirmed.isNotEmpty()) {
                    allUnconfirmed.add(unconfirmed)
                }
            }
        }

        val currTime = currentTimeSeconds()
        val inv = UnfilteredInvList()
        var poolAccepted = 0

        allUnconfirmed.forEach { unconfirmed ->
            unconfirmed.sortBy { (_, _, seq) -> seq }

            unconfirmed.forEach { (hash, bytes, _) ->
                val (status, fee) = TxPool.process(hash, bytes, currTime, false)
                when (status) {
                    Accepted -> {
                        poolAccepted += 1
                        inv.add(Pair(hash, fee))
                    }
                    is AlreadyHave -> {
                        inv.add(Pair(hash, fee))
                    }
                    else -> {
                        logger.debug { "$status ${HashSerializer.encode(hash)}" }
                    }
                }
            }
        }

        if (poolAccepted != 0) {
            logger.info("Added ${inv.size} transactions to pool")
        }

        if (inv.isNotEmpty()) {
            val n = Node.broadcastInv(inv)
            logger.info("Announced ${inv.size} transactions to $n peers")
        }

        delay(30 * 60 * 1000L)
    }

    suspend fun getConfirmations(hash: ByteArray): Int? = BlockDB.mutex.withLock {
        mutex.withLock {
            wallets.forEach { (_, wallet) ->
                val data = wallet.transactions.get(hash)
                if (data != null) {
                    return data.confirmationsImpl(LedgerDB.state())
                } else {
                    Unit
                }
            }
            return null
        }
    }

    suspend fun getConfirmations(publicKey: ByteArray, hash: ByteArray): Int? = BlockDB.mutex.withLock {
        return mutex.withLock {
            val wallet = wallets.get(publicKey)
            if (wallet != null) {
                val txData = wallet.transactions.get(hash)
                if (txData != null) {
                    txData.confirmationsImpl(LedgerDB.state())
                } else {
                    txData
                }
            } else {
                wallet
            }
        }
    }

    suspend fun getSequence(publicKey: ByteArray): Int = mutex.withLock {
        val wallet = getWalletImpl(publicKey)
        val seq = wallet.seq
        return@withLock if (seq < Config.instance.seqthreshold)
            seq
        else
            throw RuntimeException("Wallet reached sequence threshold")
    }

    internal fun getTransactionImpl(hash: ByteArray): ByteArray? {
        return LevelDB.get(TX_KEY, hash)
    }

    suspend fun disconnectBlock(blockHash: ByteArray, batch: LevelDB.WriteBatch) = mutex.withLock {
        if (wallets.isEmpty()) return@withLock

        val (block, _) = BlockDB.blockImpl(blockHash)!!
        val txHashes = block.transactions.map { Transaction.hash(it) }

        val updated = HashMap<ByteArray, Wallet>(wallets.size)
        wallets.forEach { (publicKey, wallet) ->
            val generated = wallet.transactions.get(blockHash)
            if (generated != null) {
                generated.height = 0
                updated.put(publicKey, wallet)
            }
            txHashes.forEach { hash ->
                val tx = wallet.transactions.get(hash)
                if (tx != null) {
                    tx.height = 0
                    updated.put(publicKey, wallet)
                }
            }
        }

        updated.forEach { (publicKey, wallet) ->
            batch.put(WALLET_KEY, publicKey, binaryFormat.encodeToByteArray(Wallet.serializer(), wallet))
        }
    }

    suspend fun processBlock(hash: ByteArray, block: Block?, height: Int, generated: Long, batch: LevelDB.WriteBatch) = mutex.withLock {
        wallets.forEach { (publicKey, wallet) ->
            processBlockImpl(publicKey, wallet, hash, block, height, generated, batch, false)
        }
    }

    private suspend fun processBlockImpl(publicKey: ByteArray, wallet: Wallet, hash: ByteArray, block: Block?, height: Int, generated: Long, batch: LevelDB.WriteBatch, rescan: Boolean) {
        if (height != 0) {
            if (block!!.generator.contentEquals(publicKey)) {
                val tx = Transaction.generated(publicKey, height, hash, generated)
                val txBytes = binaryFormat.encodeToByteArray(Transaction.serializer(), tx)
                val txHash = hash // re-use block hash as hash of Generated tx
                processTransactionImpl(publicKey, wallet, txHash, tx, txBytes, block.time, height, batch, rescan)
            }
        } else {
            val balance = Genesis.balances.get(publicKey) ?: return

            val tx = Transaction.generated(publicKey, height, hash, balance)
            val txBytes = binaryFormat.encodeToByteArray(Transaction.serializer(), tx)
            val txHash = Transaction.hash(txBytes)
            processTransactionImpl(publicKey, wallet, txHash, tx, txBytes, Genesis.TIME, height, batch, rescan)
        }
    }

    suspend fun processTransaction(hash: ByteArray, tx: Transaction, bytes: ByteArray, time: Long) = mutex.withLock {
        val batch = LevelDB.createWriteBatch()
        processTransactionImpl(hash, tx, bytes, time, 0, batch)
        batch.write()
    }

    suspend fun processTransaction(hash: ByteArray, tx: Transaction, bytes: ByteArray, time: Long, height: Int, batch: LevelDB.WriteBatch) = mutex.withLock {
        processTransactionImpl(hash, tx, bytes, time, height, batch)
    }

    private suspend fun processTransactionImpl(hash: ByteArray, tx: Transaction, bytes: ByteArray, time: Long, height: Int, batch: LevelDB.WriteBatch) {
        var store = !LevelDB.contains(TX_KEY, hash)

        wallets.forEach { (publicKey, wallet) ->
            if (processTransactionImpl(publicKey, wallet, hash, tx, bytes, time, height, batch, false, store))
                store = false
        }
    }

    private fun processTransactionDataImpl(publicKey: ByteArray, wallet: Wallet, hash: ByteArray, dataIndex: Int, type: Byte, bytes: ByteArray, height: Int, from: Boolean): Boolean {
        return when (type) {
            TxType.Transfer.type -> {
                if (from) {
                    true
                } else {
                    binaryFormat.decodeFromByteArray(Transfer.serializer(), bytes).involves(publicKey)
                }
            }
            TxType.Burn.type -> {
                from
            }
            TxType.Lease.type -> {
                val data = binaryFormat.decodeFromByteArray(Lease.serializer(), bytes)
                if (from) {
                    wallet.outLeases.add(AccountState.Lease(data.to, height, data.amount))
                    true
                } else {
                    data.involves(publicKey)
                }
            }
            TxType.CancelLease.type -> {
                val data = binaryFormat.decodeFromByteArray(CancelLease.serializer(), bytes)
                if (from) {
                    if (!wallet.outLeases.remove(AccountState.Lease(data.to, data.height, data.amount)))
                        logger.warn("Lease not found")
                    true
                } else {
                    data.involves(publicKey)
                }
            }
            TxType.BApp.type -> {
                from
            }
            TxType.CreateHTLC.type -> {
                val data = binaryFormat.decodeFromByteArray(CreateHTLC.serializer(), bytes)
                if (from || data.involves(publicKey)) {
                    wallet.htlcs.add(data.id(hash, dataIndex))
                    true
                } else {
                    false
                }
            }
            TxType.RefundHTLC.type -> {
                val data = binaryFormat.decodeFromByteArray(RefundHTLC.serializer(), bytes)
                if (from || data.involves(wallet.htlcs)) {
                    wallet.htlcs.remove(data.id)
                    true
                } else {
                    false
                }
            }
            TxType.CreateMultisig.type -> {
                val data = binaryFormat.decodeFromByteArray(CreateMultisig.serializer(), bytes)
                if (from || data.involves(publicKey)) {
                    wallet.multisigs.add(data.id(hash, dataIndex))
                    true
                } else {
                    false
                }
            }
            TxType.SpendMultisig.type -> {
                val data = binaryFormat.decodeFromByteArray(SpendMultisig.serializer(), bytes)
                if (from || data.involves(wallet.multisigs)) {
                    wallet.multisigs.remove(data.id)
                    true
                } else {
                    false
                }
            }
            TxType.WithdrawFromLease.type -> {
                val data = binaryFormat.decodeFromByteArray(WithdrawFromLease.serializer(), bytes)
                if (from) {
                    val lease = wallet.outLeases.find { it.publicKey.contentEquals(data.to) && it.height == data.height && it.amount == data.amount }
                    if (lease != null)
                        lease.amount -= data.withdraw
                    else
                        logger.warn("Lease not found")
                    true
                } else {
                    data.involves(publicKey)
                }
            }
            TxType.ClaimHTLC.type -> {
                val data = binaryFormat.decodeFromByteArray(ClaimHTLC.serializer(), bytes)
                if (from || data.involves(wallet.htlcs)) {
                    wallet.htlcs.remove(data.id)
                    true
                } else {
                    false
                }
            }
            else -> {
                logger.warn("Unexpected TxType $type")
                from
            }
        }
    }

    private suspend fun processTransactionImpl(publicKey: ByteArray, wallet: Wallet, hash: ByteArray, tx: Transaction, bytes: ByteArray, time: Long, height: Int, batch: LevelDB.WriteBatch, rescan: Boolean, store: Boolean = true): Boolean {
        val txData = wallet.transactions.get(hash)
        if (txData == null) {
            val from = tx.from.contentEquals(publicKey)
            val types = if (tx.type == TxType.Generated.type) {
                listOf(TransactionDataType(tx.type, 0))
            } else {
                if (from) {
                    if (tx.seq == wallet.seq)
                        wallet.seq += 1
                    else
                        logger.warn("Out of order sequence ${tx.seq} ${wallet.seq} ${HashSerializer.encode(hash)}")
                }
                if (tx.type != TxType.Batch.type) {
                    if (processTransactionDataImpl(publicKey, wallet, hash, 0, tx.type, tx.data, height, from))
                        listOf(TransactionDataType(tx.type, 0))
                    else
                        emptyList()
                } else {
                    val data = binaryFormat.decodeFromByteArray(Batch.serializer(), bytes)
                    val types = ArrayList<TransactionDataType>(data.multiData.size)
                    for (index in 0 until data.multiData.size) {
                        val (dataType, dataBytes) = data.multiData[index]
                        val dataIndex = index + 1
                        if (processTransactionDataImpl(publicKey, wallet, hash, dataIndex, dataType, dataBytes, height, from))
                            types.add(TransactionDataType(dataType, dataIndex.toByte()))
                    }
                    types
                }
            }
            if (types.isNotEmpty()) {
                wallet.transactions.put(hash, TransactionData(types, time, height))

                if (!rescan) {
                    RPCServer.walletNotify(tx, hash, time, bytes.size, publicKey, types)
                    batch.put(WALLET_KEY, publicKey, binaryFormat.encodeToByteArray(Wallet.serializer(), wallet))
                }
                if (store) {
                    batch.put(TX_KEY, hash, bytes)
                }

                return true
            } else {
                return false
            }
        } else if (txData.height != height) {
            txData.height = height

            if (!rescan) {
                batch.put(WALLET_KEY, publicKey, binaryFormat.encodeToByteArray(Wallet.serializer(), wallet))
            }

            return true
        } else {
            return false
        }
    }

    @Serializable
    class TransactionDataType(
            val type: Byte,
            val dataIndex: Byte
    ) {
        @Serializer(forClass = TransactionDataType::class)
        companion object {
            override fun deserialize(decoder: Decoder): TransactionDataType {
                return when (decoder) {
                    is BinaryDecoder -> {
                        TransactionDataType(
                                decoder.decodeByte(),
                                decoder.decodeByte()
                        )
                    }
                    else -> throw notSupportedFormatError(decoder, this)
                }
            }

            override fun serialize(encoder: Encoder, value: TransactionDataType) {
                when (encoder) {
                    is BinaryEncoder -> {
                        encoder.encodeByte(value.type)
                        encoder.encodeByte(value.dataIndex)
                    }
                    is JsonEncoder -> {
                        @Suppress("NAME_SHADOWING")
                        val encoder = encoder.beginStructure(descriptor)
                        encoder.encodeSerializableElement(descriptor, 0, Int.serializer(), value.type.toUByte().toInt())
                        encoder.encodeSerializableElement(descriptor, 1, Int.serializer(), value.dataIndex.toInt())
                        encoder.endStructure(descriptor)
                    }
                    else -> throw notSupportedFormatError(encoder, this)
                }
            }
        }
    }

    @Serializable
    class TransactionData(
            // 交易數據類型和交易數據索引號列表
            val types: List<TransactionDataType>,
            // 交易被接收了的時間戳
            @Serializable(with = VarLongSerializer::class)
            val time: Long,
            // 包含交易的區塊的高度
            @Serializable(with = VarIntSerializer::class)
            var height: Int
    ) {
        internal fun confirmationsImpl(ledger: LedgerDB.State): Int {
            return if (height != 0)
                ledger.height - height + 1
            else
                0
        }
    }

    @Serializable
    class Wallet(
            @Serializable(with = VarIntSerializer::class)
            var seq: Int = 0,
            val htlcs: HashSet<@Serializable(HashTimeLockContractIdSerializer::class) ByteArray> = HashSet(),
            val multisigs: HashSet<@Serializable(MultiSignatureLockContractIdSerializer::class) ByteArray> = HashSet(),
            val outLeases: ArrayList<AccountState.Lease> = ArrayList(),
            val transactions: HashMap<@Serializable(HashSerializer::class) ByteArray, TransactionData> = HashMap()
    )

    private fun addWalletImpl(batch: LevelDB.WriteBatch, publicKey: ByteArray, wallet: Wallet) {
        wallets.put(publicKey, wallet)
        batch.put(WALLET_KEY, publicKey, binaryFormat.encodeToByteArray(Wallet.serializer(), wallet))
        val encoder = BinaryEncoder()
        wallets.forEach { (publicKey, _) -> encoder.encodeFixedByteArray(publicKey) }
        val keysBytes = encoder.toBytes()
        batch.put(KEYS_KEY, keysBytes)
    }

    internal suspend fun getWalletImpl(publicKey: ByteArray): Wallet {
        var wallet = wallets.get(publicKey)
        if (wallet != null)
            return wallet

        logger.debug { "Creating new wallet for ${Address.encode(publicKey)}" }
        val batch = LevelDB.createWriteBatch()
        wallet = Wallet()

        mutex.withUnlock {
            BlockDB.mutex.withLock {
                mutex.withLock {
                    var hash = HashSerializer.ZERO
                    var index = LedgerDB.getChainIndex(hash)!!
                    val height = LedgerDB.state().height
                    val n = height - index.height + 1
                    if (n > 0) {
                        logger.info("Rescanning $n blocks...")
                        do {
                            rescanBlockImpl(publicKey, wallet, hash, index.height, index.generated, batch)
                            hash = index.next
                            index = LedgerDB.getChainIndex(hash)!!
                        } while (index.height != height)
                        logger.info("Finished rescan")
                    }
                }
            }
        }

        // 重掃描交易池

        addWalletImpl(batch, publicKey, wallet)
        batch.write()
        return wallet
    }

    fun referenceChain(): ByteArray {
        return if (!PoS.guessInitialSynchronization())
            LedgerDB.state().rollingCheckpoint
        else
            HashSerializer.ZERO
    }

    private suspend fun rescanBlockImpl(publicKey: ByteArray, wallet: Wallet, hash: ByteArray, height: Int, generated: Long, batch: LevelDB.WriteBatch) {
        if (height != 0) {
            val block = BlockDB.blockImpl(hash)!!.first
            processBlockImpl(publicKey, wallet, hash, block, height, generated, batch, true)
            for (bytes in block.transactions) {
                val tx = binaryFormat.decodeFromByteArray(Transaction.serializer(), bytes)
                val txHash = Transaction.hash(bytes)
                processTransactionImpl(publicKey, wallet, txHash, tx, bytes, block.time, height, batch, true)
            }
        } else {
            processBlockImpl(publicKey, wallet, hash, null, height, generated, batch, true)
        }
    }

    private fun clear(batch: LevelDB.WriteBatch) {
        val backupDir = File(dataDir, "walletdb.backup.${currentTimeSeconds()}")
        backupDir.mkdir()
        logger.info("Saving backup to $backupDir")
        wallets.clear()

        val iterator = LevelDB.iterator()

        if (LevelDB.seek(iterator, TX_KEY)) {
            val file = File(backupDir, "transactions")
            val stream = file.outputStream().buffered().data()

            while (iterator.hasNext()) {
                val entry = iterator.next()
                if (TX_KEY % entry) {
                    val bytes = entry.value
                    stream.writeInt(bytes.size)
                    stream.write(bytes, 0, bytes.size)
                    batch.delete(entry.key)
                } else {
                    break
                }
            }

            stream.close()
        }

        if (LevelDB.seek(iterator, WALLET_KEY)) {
            while (iterator.hasNext()) {
                val entry = iterator.next()
                val key = WALLET_KEY - entry ?: break
                val file = File(backupDir, Address.encode(key))
                val stream = file.outputStream().buffered().data()

                val bytes = entry.value
                stream.write(bytes, 0, bytes.size)
                batch.delete(entry.key)

                stream.close()
            }
        }

        iterator.close()
    }
}
