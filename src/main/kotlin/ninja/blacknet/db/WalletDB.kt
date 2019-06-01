/*
 * Copyright (c) 2019 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.db

import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.Serializable
import mu.KotlinLogging
import ninja.blacknet.Config
import ninja.blacknet.Config.mnemonics
import ninja.blacknet.api.APIServer
import ninja.blacknet.core.*
import ninja.blacknet.crypto.Address
import ninja.blacknet.crypto.Hash
import ninja.blacknet.crypto.Mnemonic
import ninja.blacknet.crypto.PublicKey
import ninja.blacknet.network.Node
import ninja.blacknet.network.UnfilteredInvList
import ninja.blacknet.serialization.BinaryDecoder
import ninja.blacknet.serialization.BinaryEncoder
import ninja.blacknet.transaction.CancelLease
import ninja.blacknet.transaction.Lease
import ninja.blacknet.transaction.TxType
import ninja.blacknet.util.delay
import ninja.blacknet.util.startsWith

private val logger = KotlinLogging.logger {}

object WalletDB {
    private const val DELAY = 30 * 60
    private const val VERSION = 2
    private val KEYS_KEY = "keys".toByteArray()
    private val TX_KEY = "tx".toByteArray()
    private val VERSION_KEY = "version".toByteArray()
    private val WALLET_KEY = "wallet".toByteArray()
    private val wallets = HashMap<PublicKey, Wallet>()

    private fun setVersion(batch: LevelDB.WriteBatch) {
        val version = BinaryEncoder()
        version.packInt(VERSION)
        batch.put(WALLET_KEY, VERSION_KEY, version.toBytes())
    }

    init {
        val keysBytes = LevelDB.get(WALLET_KEY, KEYS_KEY)
        val versionBytes = LevelDB.get(WALLET_KEY, VERSION_KEY)

        val version = if (versionBytes != null) {
            BinaryDecoder.fromBytes(versionBytes).unpackInt()
        } else {
            1
        }

        if (version == VERSION) {
            if (keysBytes != null) {
                val decoder = BinaryDecoder.fromBytes(keysBytes)
                for (i in 0 until keysBytes.size step PublicKey.SIZE) {
                    val publicKey = PublicKey(decoder.decodeByteArrayValue(PublicKey.SIZE))
                    wallets.put(publicKey, Wallet.deserialize(LevelDB.get(WALLET_KEY, publicKey.bytes)!!))
                }
                if (wallets.size == 1)
                    logger.info("Loaded wallet with ${wallets.values.first().transactions.size} transactions")
                else
                    logger.info("Loaded ${wallets.size} wallets")
            }
        } else if (version == 1) {
            val batch = LevelDB.createWriteBatch()
            if (keysBytes != null) {
                logger.info("Clearing WalletDB...")
                clear(batch)
            }
            setVersion(batch)
            batch.write()
        } else {
            throw RuntimeException("Unknown database version $version")
        }

        if (Config.contains(mnemonics)) {
            runBlocking {
                Config[mnemonics].forEach {
                    val privateKey = Mnemonic.fromString(it)
                    if (privateKey != null) {
                        PoS.startStaking(privateKey)
                    } else {
                        logger.warn("invalid mnemonic")
                    }
                }
                val n = PoS.stakersSize()
                if (n == 1)
                    logger.info("Started staking")
                else if (n > 1)
                    logger.info("Started staking with $n accounts")
            }
        }

        Node.launch { broadcaster() }
    }

    private suspend fun broadcaster() {
        while (true) {
            delay(DELAY)

            val inv = UnfilteredInvList()

            BlockDB.mutex.withLock {
                wallets.forEach { (_, wallet) ->
                    wallet.transactions.forEach { (hash, txData) ->
                        if (txData.height == 0) {
                            val bytes = getTransaction(hash)!!
                            val tx = Transaction.deserialize(bytes)!!
                            if (tx.type != TxType.Generated.type) {
                                val status = TxPool.process(hash, bytes)
                                if (status == DataDB.Status.ACCEPTED || status == DataDB.Status.ALREADY_HAVE) {
                                    inv.add(Triple(DataType.Transaction, hash, tx.fee))
                                } else {
                                    logger.debug { "$status tx $hash" }
                                }
                            }
                        }
                    }
                }
            }

            if (inv.isNotEmpty()) {
                logger.info("Broadcasting ${inv.size} transactions")
                Node.broadcastInv(inv)
            }
        }
    }

    suspend fun getConfirmations(hash: Hash): Int? = BlockDB.mutex.withLock {
        wallets.forEach { (_, wallet) ->
            val data = wallet.transactions.get(hash)
            if (data != null) {
                if (data.height == 0) return@withLock 0
                return@withLock LedgerDB.height() - data.height
            }
        }
        return@withLock null
    }

    suspend fun getSequence(publicKey: PublicKey): Int = BlockDB.mutex.withLock {
        return@withLock getWalletImpl(publicKey).seq
    }

    fun getTransaction(hash: Hash): ByteArray? {
        return LevelDB.get(TX_KEY, hash.bytes)
    }

    internal fun disconnectBlockImpl(blockHash: Hash, txHashes: ArrayList<Hash>) {
        val updated = HashMap<PublicKey, Wallet>(wallets.size)
        wallets.forEach { (publicKey, wallet) ->
            val generated = wallet.transactions.get(blockHash)
            if (generated != null) {
                wallet.transactions.put(blockHash, TransactionData(generated.time, 0))
                updated.put(publicKey, wallet)
            }
            txHashes.forEach { hash ->
                val tx = wallet.transactions.get(hash)
                if (tx != null) {
                    wallet.transactions.put(hash, TransactionData(tx.time, 0))
                    updated.put(publicKey, wallet)
                }
            }
        }
        if (!updated.isEmpty()) {
            val batch = LevelDB.createWriteBatch()
            updated.forEach { (publicKey, wallet) ->
                batch.put(WALLET_KEY, publicKey.bytes, wallet.serialize())
            }
            batch.write()
        }
    }

    suspend fun processBlockImpl(hash: Hash, block: Block?, height: Int, generated: Long, batch: LevelDB.WriteBatch) {
        wallets.forEach { (publicKey, wallet) ->
            processBlockImpl(publicKey, wallet, hash, block, height, generated, batch, false)
        }
    }

    private suspend fun processBlockImpl(publicKey: PublicKey, wallet: Wallet, hash: Hash, block: Block?, height: Int, generated: Long, batch: LevelDB.WriteBatch, rescan: Boolean) {
        if (height != 0) {
            if (block!!.generator == publicKey) {
                val tx = Transaction.generated(publicKey, height, hash, generated)
                processTransactionImpl(publicKey, wallet, hash, tx, tx.serialize(), block.time, height, batch, rescan)
            }
        } else {
            val genesis = LedgerDB.genesisBlock()
            for (i in genesis) {
                val key = PublicKey.fromString(i.publicKey)!!
                if (key == publicKey) {
                    val tx = Transaction.generated(publicKey, height, hash, i.balance)
                    processTransactionImpl(publicKey, wallet, publicKey.hash(), tx, tx.serialize(), LedgerDB.GENESIS_TIME, height, batch, rescan)
                    break
                }
            }
        }
    }

    suspend fun processTransaction(hash: Hash, tx: Transaction, bytes: ByteArray, time: Long) = BlockDB.mutex.withLock {
        val batch = LevelDB.createWriteBatch()
        processTransactionImpl(hash, tx, bytes, time, 0, batch)
        batch.write()
    }

    internal suspend fun processTransactionImpl(hash: Hash, tx: Transaction, bytes: ByteArray, time: Long, height: Int, batch: LevelDB.WriteBatch) {
        var store = !LevelDB.contains(TX_KEY, hash.bytes)

        wallets.forEach { (publicKey, wallet) ->
            if (processTransactionImpl(publicKey, wallet, hash, tx, bytes, time, height, batch, false, store))
                store = false
        }
    }

    private suspend fun processTransactionImpl(publicKey: PublicKey, wallet: Wallet, hash: Hash, tx: Transaction, bytes: ByteArray, time: Long, height: Int, batch: LevelDB.WriteBatch, rescan: Boolean, store: Boolean = true): Boolean {
        var added = false
        var updated = false

        val from = tx.from == publicKey
        if (from || tx.data()!!.involves(publicKey)) {
            val txData = wallet.transactions.get(hash)
            if (txData == null) {
                wallet.transactions.put(hash, TransactionData(time, height))
                if (from && tx.type != TxType.Generated.type) {
                    if (tx.seq == wallet.seq)
                        wallet.seq++
                    else
                        logger.warn("Out of order sequence ${tx.seq} ${wallet.seq} $hash")
                }
                added = true
            } else if (txData.height != height) {
                txData.height = height
                updated = true
            }
        }

        if (added) {
            if (!rescan) {
                APIServer.transactionNotify(tx, hash, time, bytes.size, publicKey)
                batch.put(WALLET_KEY, publicKey.bytes, wallet.serialize())
            }
            if (store)
                batch.put(TX_KEY, hash.bytes, bytes)
            return true
        } else if (updated) {
            if (!rescan)
                batch.put(WALLET_KEY, publicKey.bytes, wallet.serialize())
            return true
        } else {
            return false
        }
    }

    @Serializable
    class TransactionData(val time: Long, var height: Int)

    @Serializable
    class Wallet(
            var seq: Int = 0,
            val transactions: HashMap<Hash, TransactionData> = HashMap()
    ) {
        fun serialize(): ByteArray {
            val encoder = BinaryEncoder()
            encoder.packInt(seq)
            encoder.packInt(transactions.size)
            for ((hash, data) in transactions) {
                encoder.encodeByteArrayValue(hash.bytes)
                encoder.packLong(data.time)
                encoder.packInt(data.height)
            }
            return encoder.toBytes()
        }

        companion object {
            fun deserialize(bytes: ByteArray): Wallet {
                val decoder = BinaryDecoder.fromBytes(bytes)
                val seq = decoder.unpackInt()
                val size = decoder.unpackInt()
                val wallet = Wallet(seq, HashMap(size * 2))
                for (i in 0 until size)
                    wallet.transactions.put(Hash(decoder.decodeByteArrayValue(Hash.SIZE)), TransactionData(decoder.unpackLong(), decoder.unpackInt()))
                return wallet
            }
        }
    }

    private fun addWalletImpl(batch: LevelDB.WriteBatch, publicKey: PublicKey, wallet: Wallet) {
        wallets.put(publicKey, wallet)
        batch.put(WALLET_KEY, publicKey.bytes, wallet.serialize())
        val encoder = BinaryEncoder()
        wallets.forEach { (publicKey, _) -> encoder.encodeByteArrayValue(publicKey.bytes) }
        val keysBytes = encoder.toBytes()
        batch.put(WALLET_KEY, KEYS_KEY, keysBytes)
    }

    internal suspend fun getWalletImpl(publicKey: PublicKey, rescan: Boolean = true): Wallet {
        var wallet = wallets.get(publicKey)
        if (wallet != null)
            return wallet

        logger.debug { "Creating new wallet for ${Address.encode(publicKey)}" }
        val batch = LevelDB.createWriteBatch()
        wallet = Wallet()

        if (!rescan) {
            addWalletImpl(batch, publicKey, wallet)
            batch.write()
            return wallet
        }

        var hash = Hash.ZERO
        var index = LedgerDB.getChainIndex(hash)!!
        val height = LedgerDB.height()
        val n = height - index.height + 1
        if (n > 0) {
            logger.info("Rescanning $n blocks...")
            do {
                rescanBlockImpl(publicKey, wallet, hash, index.height, index.generated, batch)
                hash = index.next
                index = LedgerDB.getChainIndex(hash)!!
            } while (index.height != height)
        }

        addWalletImpl(batch, publicKey, wallet)
        batch.write()
        return wallet
    }

    suspend fun getOutLeases(publicKey: PublicKey): List<AccountState.Lease> = BlockDB.mutex.withLock {
        val wallet = getWalletImpl(publicKey)
        val leases = ArrayList<AccountState.Lease>()
        val cancels = ArrayList<AccountState.Lease>()

        wallet.transactions.forEach { (hash, txData) ->
            val tx = Transaction.deserialize(getTransaction(hash)!!)!!
            if (tx.type == TxType.Lease.type) {
                val data = Lease.deserialize(tx.data.array)!!
                leases.add(AccountState.Lease(data.to, txData.height, data.amount))
            } else if (tx.type == TxType.CancelLease.type) {
                val data = CancelLease.deserialize(tx.data.array)!!
                cancels.add(AccountState.Lease(data.to, data.height, data.amount))
            }
        }

        cancels.forEach { leases.remove(it) }

        return@withLock leases
    }

    private suspend fun rescanBlockImpl(publicKey: PublicKey, wallet: Wallet, hash: Hash, height: Int, generated: Long, batch: LevelDB.WriteBatch) {
        if (height != 0) {
            val block = BlockDB.block(hash)!!.first
            processBlockImpl(publicKey, wallet, hash, block, height, generated, batch, true)
            for (bytes in block.transactions) {
                val tx = Transaction.deserialize(bytes.array)!!
                val txHash = Transaction.Hasher(bytes.array)
                processTransactionImpl(publicKey, wallet, txHash, tx, bytes.array, block.time, height, batch, true)
            }
        } else {
            processBlockImpl(publicKey, wallet, hash, null, height, generated, batch, true)
        }
    }

    private fun clear(batch: LevelDB.WriteBatch = LevelDB.createWriteBatch()) {
        val iterator = LevelDB.iterator()
        iterator.seekToFirst()
        while (iterator.hasNext()) {
            val entry = iterator.next()
            if (entry.key.startsWith(WALLET_KEY) ||
                    entry.key.startsWith(TX_KEY)) {
                batch.delete(entry.key)
            }
        }
        iterator.close()

        wallets.clear()
    }
}
