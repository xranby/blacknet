/*
 * Copyright (c) 2019 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.db

import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.Serializable
import mu.KotlinLogging
import ninja.blacknet.Config
import ninja.blacknet.Config.mnemonics
import ninja.blacknet.api.APIServer
import ninja.blacknet.core.Block
import ninja.blacknet.core.PoS
import ninja.blacknet.core.Transaction
import ninja.blacknet.crypto.Address
import ninja.blacknet.crypto.Hash
import ninja.blacknet.crypto.Mnemonic
import ninja.blacknet.crypto.PublicKey
import ninja.blacknet.serialization.BinaryDecoder
import ninja.blacknet.serialization.BinaryEncoder

private val logger = KotlinLogging.logger {}

object WalletDB {
    internal val mutex = Mutex()
    private val KEYS_KEY = "keys".toByteArray()
    private val TX_KEY = "tx".toByteArray()
    private val WALLET_KEY = "wallet".toByteArray()
    internal val wallets = HashMap<PublicKey, Wallet>()

    init {
        val keysBytes = LevelDB.get(WALLET_KEY, KEYS_KEY)
        if (keysBytes != null) {
            val decoder = BinaryDecoder.fromBytes(keysBytes)
            for (i in 0 until keysBytes.size step PublicKey.SIZE) {
                val publicKey = PublicKey(decoder.decodeByteArrayValue(PublicKey.SIZE))
                wallets.put(publicKey, Wallet.deserialize(LevelDB.get(WALLET_KEY, publicKey.bytes)!!))
            }
            logger.info("Loaded ${wallets.size} wallets")
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
    }

    suspend fun getConfirmations(hash: Hash): Int? = mutex.withLock {
        wallets.forEach { (_, wallet) ->
            val data = wallet.transactions.get(hash)
            if (data != null) {
                if (data.height == 0) return@withLock 0
                return@withLock LedgerDB.height() - data.height
            }
        }
        return@withLock null
    }

    fun getTransaction(hash: Hash): ByteArray? {
        return LevelDB.get(TX_KEY, hash.bytes)
    }

    suspend fun disconnectBlock(blockHash: Hash, txHashes: ArrayList<Hash>) = mutex.withLock {
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

    internal suspend fun processBlockImpl(batch: LevelDB.WriteBatch, publicKey: PublicKey, wallet: Wallet, hash: Hash, block: Block?, height: Int, generated: Long) {
        if (height != 0) {
            if (block!!.generator == publicKey) {
                val tx = Transaction.generated(publicKey, height, hash, generated)
                processTransactionImpl(publicKey, wallet, hash, tx, tx.serialize(), block.time, height, batch, false)
            }
        } else {
            val genesis = LedgerDB.genesisBlock()
            for (i in genesis) {
                val key = PublicKey.fromString(i.publicKey)!!
                if (key == publicKey) {
                    val tx = Transaction.generated(publicKey, height, hash, i.balance)
                    processTransactionImpl(publicKey, wallet, publicKey.hash(), tx, tx.serialize(), LedgerDB.GENESIS_TIME, height, batch, false)
                    break
                }
            }
        }
    }

    suspend fun processTransaction(hash: Hash, tx: Transaction, bytes: ByteArray, time: Long, height: Int, b: LevelDB.WriteBatch? = null) = mutex.withLock {
        wallets.forEach { (publicKey, wallet) ->
            processTransactionImpl(publicKey, wallet, hash, tx, bytes, time, height, b)
        }
    }

    internal suspend fun processTransactionImpl(publicKey: PublicKey, wallet: Wallet, hash: Hash, tx: Transaction, bytes: ByteArray, time: Long, height: Int, b: LevelDB.WriteBatch? = null, notify: Boolean = true) {
        val write = b == null
        val batch = b ?: LevelDB.createWriteBatch()
        val addedTo = ArrayList<PublicKey>(wallets.size)
        var added = false

        if (tx.from == publicKey || tx.data()!!.involves(publicKey)) {
            addedTo.add(publicKey)
            wallet.transactions.put(hash, TransactionData(time, height))
            batch.put(WALLET_KEY, publicKey.bytes, wallet.serialize())
            if (!added) {
                batch.put(TX_KEY, hash.bytes, bytes)
                added = true
            }
        }

        if (write)
            batch.write()

        if (notify && added)
            addedTo.forEach { APIServer.transactionNotify(tx, hash, time, bytes.size, it) }
    }

    @Serializable
    class TransactionData(val time: Long, val height: Int)

    @Serializable
    class Wallet(val transactions: HashMap<Hash, TransactionData> = HashMap()) {
        fun serialize(): ByteArray {
            val encoder = BinaryEncoder()
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
                val size = decoder.unpackInt()
                val wallet = Wallet(HashMap(size * 2))
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

    suspend fun getWallet(publicKey: PublicKey, rescan: Boolean = true): Wallet = mutex.withLock {
        var wallet = wallets.get(publicKey)
        if (wallet != null)
            return@withLock wallet

        logger.info("Creating new wallet for ${Address.encode(publicKey)}")
        val batch = LevelDB.createWriteBatch()
        wallet = Wallet()

        if (!rescan) {
            addWalletImpl(batch, publicKey, wallet)
            batch.write()
            return@withLock wallet
        }

        var hash = Hash.ZERO
        var index = LedgerDB.getChainIndex(hash)!!
        val finalized = Math.max(0, LedgerDB.height() - PoS.MATURITY - 1)
        if (finalized > 0) {
            logger.info("Rescanning $finalized finalized blocks...")
            while (index.height <= finalized) {
                scanBlockImpl(batch, publicKey, wallet, hash, index.height, index.generated)
                hash = index.next
                index = LedgerDB.getChainIndex(hash)!!
            }
        }

        LedgerDB.mutex.withLock {
            val height = LedgerDB.height()
            val n = height - index.height
            if (n > 0) {
                logger.info("Rescanning last $n blocks...")
                while (index.height != height) {
                    scanBlockImpl(batch, publicKey, wallet, hash, index.height, index.generated)
                    hash = index.next
                    index = LedgerDB.getChainIndex(hash)!!
                }
            }
        }

        addWalletImpl(batch, publicKey, wallet)
        batch.write()
        return@withLock wallet
    }

    private suspend fun scanBlockImpl(batch: LevelDB.WriteBatch, publicKey: PublicKey, wallet: Wallet, hash: Hash, height: Int, generated: Long) {
        if (height != 0) {
            val block = BlockDB.block(hash)!!.first
            processBlockImpl(batch, publicKey, wallet, hash, block, height, generated)
            for (bytes in block.transactions) {
                val tx = Transaction.deserialize(bytes.array)
                if (tx == null) {
                    logger.error("deserialization failed")
                    continue
                }
                processTransactionImpl(publicKey, wallet, hash, tx, bytes.array, block.time, height, batch, false)
            }
        } else {
            processBlockImpl(batch, publicKey, wallet, hash, null, height, generated)
        }
    }
}
