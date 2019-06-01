/*
 * Copyright (c) 2018 Pavel Vasin
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
import kotlinx.serialization.list
import mu.KotlinLogging
import ninja.blacknet.core.*
import ninja.blacknet.crypto.BigInt
import ninja.blacknet.crypto.Blake2b
import ninja.blacknet.crypto.Hash
import ninja.blacknet.crypto.PublicKey
import ninja.blacknet.serialization.BinaryDecoder
import ninja.blacknet.serialization.BinaryEncoder
import ninja.blacknet.serialization.Json
import ninja.blacknet.util.startsWith
import java.io.File
import java.util.ArrayDeque

private val logger = KotlinLogging.logger {}

object LedgerDB {
    val mutex = Mutex()
    private const val VERSION = 3
    private val ACCOUNT_KEY = "account".toByteArray()
    private val CHAIN_KEY = "chain".toByteArray()
    private val HTLC_KEY = "htlc".toByteArray()
    private val MULTISIG_KEY = "multisig".toByteArray()
    private val UNDO_KEY = "undo".toByteArray()
    private val SIZES_KEY = "ledgersizes".toByteArray()
    private val STATE_KEY = "ledgerstate".toByteArray()
    private val VERSION_KEY = "ledgerversion".toByteArray()

    const val GENESIS_TIME = 1545555600L
    private fun genesisState() = State(0, Hash.ZERO, GENESIS_TIME, PoS.INITIAL_DIFFICULTY, BigInt.ZERO, 0, Hash.ZERO, Hash.ZERO)

    fun genesisBlock(): List<GenesisEntry> {
        val bytes = File("config/genesis.json").readBytes()
        logger.info("Loaded genesis.json ${Blake2b.hash(bytes)}")
        val genesis = String(bytes)
        return Json.parse(GenesisEntry.serializer().list, genesis)
    }

    @Serializable
    class GenesisEntry(val publicKey: String, val balance: Long)

    @Serializable
    private class State(
            @Volatile
            var height: Int,
            @Volatile
            var blockHash: Hash,
            @Volatile
            var blockTime: Long,
            @Volatile
            var difficulty: BigInt,
            @Volatile
            var cumulativeDifficulty: BigInt,
            @Volatile
            var supply: Long,
            @Volatile
            var nxtrng: Hash,
            @Volatile
            var rollingCheckpoint: Hash
    ) {
        fun serialize(): ByteArray = BinaryEncoder.toBytes(serializer(), this)

        companion object {
            fun deserialize(bytes: ByteArray): State? = BinaryDecoder.fromBytes(bytes).decode(serializer())
        }
    }
    private var state: State = genesisState()

    private val blockSizes = ArrayDeque<Int>(PoS.BLOCK_SIZE_SPAN)
    const val DEFAULT_MAX_BLOCK_SIZE = 100000
    private var maxBlockSize: Int

    private fun loadGenesisState() {
        val genesis = genesisBlock()
        val batch = LevelDB.createWriteBatch()

        var supply = 0L
        for (i in genesis) {
            val publicKey = PublicKey.fromString(i.publicKey)!!
            val account = AccountState.create(i.balance)
            batch.put(ACCOUNT_KEY, publicKey.bytes, account.serialize())
            supply += i.balance
        }

        val chainIndex = ChainIndex(Hash.ZERO, Hash.ZERO, 0, 0, 0)
        batch.put(CHAIN_KEY, Hash.ZERO.bytes, chainIndex.serialize())

        blockSizes.add(0)
        state.supply = supply
        batch.put(STATE_KEY, state.serialize())

        val version = BinaryEncoder()
        version.packInt(VERSION)
        batch.put(VERSION_KEY, version.toBytes())

        batch.write()
    }

    init {
        val blockSizesBytes = LevelDB.get(SIZES_KEY)
        if (blockSizesBytes != null) {
            val decoder = BinaryDecoder.fromBytes(blockSizesBytes)
            val size = decoder.unpackInt()
            for (i in 0 until size)
                blockSizes.addLast(decoder.unpackInt())
        }
        maxBlockSize = calcMaxBlockSize()

        val stateBytes = LevelDB.get(STATE_KEY)
        if (stateBytes != null) {
            val versionBytes = LevelDB.get(VERSION_KEY)!!
            val version = BinaryDecoder.fromBytes(versionBytes).unpackInt()

            if (version == VERSION) {
                state = LedgerDB.State.deserialize(stateBytes)!!
                logger.info("Blockchain height ${state.height}")
            } else if (version == 2 || version == 1) {
                state = LedgerDB.State.deserialize(stateBytes)!!
                logger.info("Reindexing ${state.height} blocks...")

                runBlocking {
                    val blocks = ArrayList<ByteArray>(state.height)
                    val blockHashes = ArrayList<Hash>(state.height)
                    var index = getChainIndex(Hash.ZERO)!!
                    while (index.next != Hash.ZERO) {
                        blocks.add(BlockDB.get(index.next)!!)
                        blockHashes.add(index.next)
                        index = getChainIndex(index.next)!!
                    }

                    clear()

                    for (i in 0 until blockHashes.size) {
                        val hash = blockHashes[i]
                        val bytes = blocks[i]
                        val block = Block.deserialize(bytes)!!
                        val batch = LevelDB.createWriteBatch()
                        val txDb = Update(batch, hash, block.time, bytes.size, block.generator)
                        processBlockImpl(txDb, hash, block, bytes.size)
                        pruneImpl(batch)
                        txDb.commitImpl()
                    }
                }
            } else {
                throw RuntimeException("Unknown database version $version")
            }

        } else {
            loadGenesisState()
        }
    }

    fun height(): Int {
        return state.height
    }

    fun blockHash(): Hash {
        return state.blockHash
    }

    fun blockTime(): Long {
        return state.blockTime
    }

    fun difficulty(): BigInt {
        return state.difficulty
    }

    fun cumulativeDifficulty(): BigInt {
        return state.cumulativeDifficulty
    }

    fun supply(): Long {
        return state.supply
    }

    fun nxtrng(): Hash {
        return state.nxtrng
    }

    fun rollingCheckpoint(): Hash {
        return state.rollingCheckpoint
    }

    fun chainContains(hash: Hash): Boolean {
        return LevelDB.contains(CHAIN_KEY, hash.bytes)
    }

    internal fun getNextRollingCheckpoint(): Hash {
        if (state.rollingCheckpoint != Hash.ZERO) {
            val chainIndex = getChainIndex(state.rollingCheckpoint)!!
            return chainIndex.next
        } else {
            if (state.height < PoS.MATURITY + 1)
                return Hash.ZERO
            val checkpoint = state.height - PoS.MATURITY
            var chainIndex = getChainIndex(state.blockHash)!!
            while (chainIndex.height != checkpoint + 1)
                chainIndex = getChainIndex(chainIndex.previous)!!
            return chainIndex.previous
        }
    }

    fun get(key: PublicKey): AccountState? {
        val bytes = LevelDB.get(ACCOUNT_KEY, key.bytes) ?: return null
        return AccountState.deserialize(bytes)!!
    }

    private fun set(key: PublicKey, state: AccountState) {
        LevelDB.put(ACCOUNT_KEY, key.bytes, state.serialize())
    }

    private fun remove(key: PublicKey) {
        LevelDB.delete(ACCOUNT_KEY, key.bytes)
    }

    private fun setSupply(amount: Long) {
        state.supply = amount
    }

    private fun getUndo(hash: Hash): UndoBlock {
        return UndoBlock.deserialize(LevelDB.get(UNDO_KEY, hash.bytes)!!)!!
    }

    private fun removeUndo(hash: Hash) {
        LevelDB.delete(UNDO_KEY, hash.bytes)
    }

    fun getChainIndex(hash: Hash): ChainIndex? {
        val bytes = LevelDB.get(CHAIN_KEY, hash.bytes) ?: return null
        return ChainIndex.deserialize(bytes)!!
    }

    private fun setChainIndex(hash: Hash, chainIndex: ChainIndex) {
        LevelDB.put(CHAIN_KEY, hash.bytes, chainIndex.serialize())
    }

    private fun removeChainIndex(hash: Hash) {
        LevelDB.delete(CHAIN_KEY, hash.bytes)
    }

    fun checkBlockHash(hash: Hash) = hash == Hash.ZERO || chainContains(hash)

    fun maxBlockSize(): Int {
        return maxBlockSize
    }

    suspend fun getNextBlockHashes(start: Hash, max: Int): ArrayList<Hash> = mutex.withLock {
        var chainIndex = getChainIndex(start) ?: return@withLock ArrayList()
        val result = ArrayList<Hash>(max)
        while (true) {
            val hash = chainIndex.next
            if (hash == Hash.ZERO)
                break
            result.add(hash)
            if (result.size == max)
                break
            chainIndex = getChainIndex(chainIndex.next)!!
        }
        return result
    }

    fun getBlockNumber(hash: Hash): Int? {
        val bytes = LevelDB.get(CHAIN_KEY, hash.bytes) ?: return null
        return ChainIndex.deserialize(bytes)!!.height
    }

    private fun addHTLC(id: Hash, htlc: HTLC) {
        LevelDB.put(HTLC_KEY, id.bytes, htlc.serialize())
    }

    fun getHTLC(id: Hash): HTLC? {
        val bytes = LevelDB.get(HTLC_KEY, id.bytes) ?: return null
        return HTLC.deserialize(bytes)!!
    }

    private fun removeHTLC(id: Hash) {
        LevelDB.delete(HTLC_KEY, id.bytes)
    }

    private fun addMultisig(id: Hash, multisig: Multisig) {
        LevelDB.put(MULTISIG_KEY, id.bytes, multisig.serialize())
    }

    fun getMultisig(id: Hash): Multisig? {
        val bytes = LevelDB.get(MULTISIG_KEY, id.bytes) ?: return null
        return Multisig.deserialize(bytes)!!
    }

    private fun removeMultisig(id: Hash) {
        LevelDB.delete(MULTISIG_KEY, id.bytes)
    }

    private fun calcMaxBlockSize(): Int {
        if (blockSizes.size < PoS.BLOCK_SIZE_SPAN)
            return DEFAULT_MAX_BLOCK_SIZE
        val iterator = blockSizes.iterator()
        val sizes = Array(PoS.BLOCK_SIZE_SPAN) { iterator.next() }
        sizes.sort()
        val median = sizes[PoS.BLOCK_SIZE_SPAN / 2]
        return Math.max(DEFAULT_MAX_BLOCK_SIZE, median * 2)
    }

    internal suspend fun processBlockImpl(txDb: Update, hash: Hash, block: Block, size: Int): Boolean {
        if (block.previous != blockHash()) {
            logger.error("not on current chain")
            return false
        }
        if (size > maxBlockSize()) {
            logger.info("too large block $size bytes, maximum ${maxBlockSize()}")
            return false
        }
        if (block.time <= blockTime()) {
            logger.info("timestamp is too early")
            return false
        }
        val generator = txDb.get(block.generator)
        if (generator == null) {
            logger.info("block generator not found")
            return false
        }
        val height = txDb.height()

        val undo = UndoBuilder(
                blockTime(),
                difficulty(),
                cumulativeDifficulty(),
                supply(),
                nxtrng(),
                rollingCheckpoint(),
                blockSizes.peekFirst(),
                ArrayList(block.transactions.size))

        if (!PoS.check(block.time, block.generator, undo.nxtrng, undo.difficulty, undo.blockTime, generator.stakingBalance(height))) {
            logger.info("invalid proof of stake")
            return false
        }

        var fees = 0L
        WalletDB.mutex.withLock {
            for (bytes in block.transactions) {
                val tx = Transaction.deserialize(bytes.array)
                if (tx == null) {
                    logger.info("deserialization failed")
                    return false
                }
                val txHash = Transaction.Hasher(bytes.array)
                if (!txDb.processTransactionImpl(tx, txHash, bytes.array.size, undo)) {
                    logger.info("invalid tx $txHash")
                    return false
                }
                undo.txHashes.add(txHash)
                fees += tx.fee

                WalletDB.wallets.forEach { (publicKey, wallet) ->
                    WalletDB.processTransactionImpl(publicKey, wallet, txHash, tx, bytes.array, block.time, height, txDb.batch)
                }
            }

            @Suppress("NAME_SHADOWING")
            val generator = txDb.get(block.generator)!!
            undo.add(block.generator, generator)
            txDb.addUndo(hash, undo.build())

            val reward = PoS.reward(supply())
            val generated = reward + fees

            val prevIndex = txDb.getChainIndex(block.previous)!!
            prevIndex.next = hash
            prevIndex.nextSize = size
            txDb.setChainIndex(block.previous, prevIndex)
            txDb.setChainIndex(hash, ChainIndex(block.previous, Hash.ZERO, 0, height, generated))

            txDb.addSupply(reward)
            generator.prune(height)
            generator.debit(height, generated)
            txDb.set(block.generator, generator)

            WalletDB.wallets.forEach { (publicKey, wallet) ->
                WalletDB.processBlockImpl(txDb.batch, publicKey, wallet, hash, block, height, generated)
            }
        }

        TxPool.mutex.withLock {
            TxPool.clearRejectsImpl()
            TxPool.removeImpl(undo.txHashes)
        }

        return true
    }

    private suspend fun undoBlock(): Hash {
        val hash = blockHash()
        val chainIndex = getChainIndex(hash)!!
        val undo = getUndo(hash)

        val height = state.height
        state.height = height - 1
        state.cumulativeDifficulty = undo.cumulativeDifficulty
        state.blockHash = chainIndex.previous
        state.blockTime = undo.blockTime
        state.difficulty = undo.difficulty
        blockSizes.removeLast()
        blockSizes.addFirst(undo.blockSize)
        state.nxtrng = undo.nxtrng
        state.rollingCheckpoint = undo.rollingCheckpoint

        val prevIndex = getChainIndex(chainIndex.previous)!!
        prevIndex.next = Hash.ZERO
        prevIndex.nextSize = 0
        setChainIndex(chainIndex.previous, prevIndex)
        removeChainIndex(hash)

        setSupply(undo.supply)
        undo.accounts.forEach {
            val key = it.first
            val state = it.second
            if (state.isEmpty())
                remove(key)
            else
                set(key, state)
        }
        undo.htlcs.forEach {
            val id = it.first
            val htlc = it.second
            if (htlc != null)
                addHTLC(id, htlc)
            else
                removeHTLC(id)
        }
        undo.multisigs.forEach {
            val id = it.first
            val multisig = it.second
            if (multisig != null)
                addMultisig(id, multisig)
            else
                removeMultisig(id)
        }

        removeUndo(hash)

        WalletDB.disconnectBlock(hash, undo.txHashes)

        return hash
    }

    internal suspend fun rollbackTo(hash: Hash): ArrayList<Hash> = mutex.withLock {
        return@withLock rollbackToImpl(hash)
    }

    private suspend fun rollbackToImpl(hash: Hash): ArrayList<Hash> {
        val i = getBlockNumber(hash) ?: return ArrayList()
        val height = height()
        var n = height - i
        if (n <= 0) throw RuntimeException("Rollback of $n blocks")
        val result = ArrayList<Hash>(n)
        while (n-- > 0)
            result.add(undoBlock())
        return result
    }

    internal suspend fun undoRollback(hash: Hash, list: ArrayList<Hash>): ArrayList<Hash> = mutex.withLock {
        val toRemove = rollbackToImpl(hash)

        list.asReversed().forEach {
            val block = BlockDB.block(it)
            if (block == null) {
                logger.error("block not found")
                return@withLock toRemove
            }

            val batch = LevelDB.createWriteBatch()
            val txDb = LedgerDB.Update(batch, it, block.first.time, block.second, block.first.generator)
            if (!processBlockImpl(txDb, it, block.first, block.second)) {
                batch.close()
                logger.error("process block failed")
                return@withLock toRemove
            }
            txDb.commitImpl()
        }

        return@withLock toRemove
    }

    internal suspend fun prune() = mutex.withLock {
        val batch = LevelDB.createWriteBatch()
        pruneImpl(batch)
        batch.write()
    }

    internal fun pruneImpl(batch: LevelDB.WriteBatch) {
        var chainIndex = getChainIndex(rollingCheckpoint()) ?: return
        while (true) {
            val hash = chainIndex.previous
            if (!LevelDB.contains(UNDO_KEY, hash.bytes))
                break
            batch.delete(UNDO_KEY, hash.bytes)
            if (hash == Hash.ZERO)
                break
            chainIndex = getChainIndex(hash)!!
        }
    }

    private fun clear() {
        val batch = LevelDB.createWriteBatch()
        val iterator = LevelDB.iterator()
        iterator.seekToFirst()
        while (iterator.hasNext()) {
            val entry = iterator.next()
            if (entry.key.startsWith(ACCOUNT_KEY) ||
                    entry.key.startsWith(CHAIN_KEY) ||
                    entry.key.startsWith(HTLC_KEY) ||
                    entry.key.startsWith(MULTISIG_KEY) ||
                    entry.key.startsWith(UNDO_KEY) ||
                    entry.key!!.contentEquals(SIZES_KEY) ||
                    entry.key!!.contentEquals(STATE_KEY) ||
                    entry.key!!.contentEquals(VERSION_KEY)) {
                batch.delete(entry.key)
            }
        }
        batch.write()

        blockSizes.clear()
        state = genesisState()

        loadGenesisState()
    }

    suspend fun check(): Check = mutex.withLock {
        var supply = 0L
        val result = Check(false, 0, 0, 0)
        val iterator = LevelDB.iterator()
        iterator.seekToFirst()
        while (iterator.hasNext()) {
            val entry = iterator.next()
            if (entry.key.startsWith(ACCOUNT_KEY)) {
                supply += AccountState.deserialize(entry.value)!!.totalBalance()
                result.accounts++
            } else if (entry.key.startsWith(HTLC_KEY)) {
                supply += HTLC.deserialize(entry.value)!!.amount
                result.htlcs++
            } else if (entry.key.startsWith(MULTISIG_KEY)) {
                supply += Multisig.deserialize(entry.value)!!.amount
                result.multisigs++
            }
        }
        iterator.close()
        if (supply == state.supply)
            result.result = true
        return@withLock result
    }

    @Serializable
    class Check(
            var result: Boolean,
            var accounts: Int,
            var htlcs: Int,
            var multisigs: Int
    )

    internal class Update(
            val batch: LevelDB.WriteBatch,
            private val blockHash: Hash,
            private val blockTime: Long,
            private val blockSize: Int,
            private val blockGenerator: PublicKey,
            private val height: Int = LedgerDB.height() + 1,
            private var supply: Long = LedgerDB.supply(),
            private val rollingCheckpoint: Hash = LedgerDB.getNextRollingCheckpoint(),
            private val accounts: MutableMap<PublicKey, AccountState> = HashMap(),
            private val htlcs: MutableMap<Hash, HTLC?> = HashMap(),
            private val multisigs: MutableMap<Hash, Multisig?> = HashMap(),
            private var undo: UndoBlock? = null,
            private var chainIndex: MutableMap<Hash, ChainIndex> = HashMap()
    ) : Ledger {
        fun getChainIndex(hash: Hash): ChainIndex? {
            return (chainIndex.get(hash) ?: LedgerDB.getChainIndex(hash))
        }

        fun setChainIndex(hash: Hash, chainIndex: ChainIndex) {
            this.chainIndex.put(hash, chainIndex)
        }

        override fun addSupply(amount: Long) {
            supply += amount
        }

        override fun addUndo(hash: Hash, undo: UndoBlock) {
            check(hash == blockHash && this.undo == null)
            this.undo = undo
        }

        override fun checkBlockHash(hash: Hash): Boolean {
            return hash == blockHash || LedgerDB.checkBlockHash(hash)
        }

        override fun checkFee(size: Int, amount: Long): Boolean {
            return amount >= 0
        }

        override fun blockTime(): Long {
            return blockTime
        }

        override fun height(): Int {
            return height
        }

        override suspend fun get(key: PublicKey): AccountState? {
            return (accounts.get(key) ?: LedgerDB.get(key))
        }

        override suspend fun set(key: PublicKey, state: AccountState) {
            accounts.set(key, state)
        }

        override fun addHTLC(id: Hash, htlc: HTLC) {
            htlcs.put(id, htlc)
        }

        override fun getHTLC(id: Hash): HTLC? {
            if (!htlcs.containsKey(id))
                return LedgerDB.getHTLC(id)
            return htlcs.get(id)
        }

        override fun removeHTLC(id: Hash) {
            htlcs.put(id, null)
        }

        override fun addMultisig(id: Hash, multisig: Multisig) {
            multisigs.put(id, multisig)
        }

        override fun getMultisig(id: Hash): Multisig? {
            if (!multisigs.containsKey(id))
                return LedgerDB.getMultisig(id)
            return multisigs.get(id)
        }

        override fun removeMultisig(id: Hash) {
            multisigs.put(id, null)
        }

        fun commitImpl() {
            batch.put(UNDO_KEY, blockHash.bytes, undo!!.serialize())
            for (chainIndex in chainIndex)
                batch.put(CHAIN_KEY, chainIndex.key.bytes, chainIndex.value.serialize())
            for (account in accounts)
                batch.put(ACCOUNT_KEY, account.key.bytes, account.value.serialize())
            for (htlc in htlcs)
                if (htlc.value != null)
                    batch.put(HTLC_KEY, htlc.key.bytes, htlc.value!!.serialize())
                else
                    batch.delete(HTLC_KEY, htlc.key.bytes)
            for (multisig in multisigs)
                if (multisig.value != null)
                    batch.put(MULTISIG_KEY, multisig.key.bytes, multisig.value!!.serialize())
                else
                    batch.delete(MULTISIG_KEY, multisig.key.bytes)

            state.blockHash = blockHash
            state.blockTime = blockTime
            state.height = height
            state.supply = supply
            state.nxtrng = PoS.nxtrng(LedgerDB.nxtrng(), blockGenerator)
            state.rollingCheckpoint = rollingCheckpoint
            val difficulty = PoS.nextDifficulty(undo!!.difficulty, undo!!.blockTime, blockTime)
            state.difficulty = difficulty
            state.cumulativeDifficulty = PoS.cumulativeDifficulty(undo!!.cumulativeDifficulty, difficulty)
            batch.put(STATE_KEY, state.serialize())

            if (blockSizes.size == PoS.BLOCK_SIZE_SPAN)
                blockSizes.removeFirst()
            blockSizes.addLast(blockSize)
            maxBlockSize = calcMaxBlockSize()
            val encoder = BinaryEncoder()
            encoder.packInt(blockSizes.size)
            for (size in blockSizes)
                encoder.packInt(size)
            batch.put(SIZES_KEY, encoder.toBytes())

            batch.write()
        }
    }
}
