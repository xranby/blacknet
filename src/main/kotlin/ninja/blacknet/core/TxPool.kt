/*
 * Copyright (c) 2018-2019 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.core

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import mu.KotlinLogging
import ninja.blacknet.Config
import ninja.blacknet.api.APIServer
import ninja.blacknet.crypto.Hash
import ninja.blacknet.crypto.PublicKey
import ninja.blacknet.db.LedgerDB
import ninja.blacknet.db.WalletDB
import ninja.blacknet.network.Node
import ninja.blacknet.serialization.SerializableByteArray
import kotlin.math.min

private val logger = KotlinLogging.logger {}

object TxPool : MemPool(), Ledger {
    internal val mutex = Mutex()
    private val rejects = HashSet<Hash>()
    private val undoAccounts = HashMap<PublicKey, AccountState?>()
    private val undoHtlcs = HashMap<Hash, Pair<Boolean, HTLC?>>()
    private val undoMultisigs = HashMap<Hash, Pair<Boolean, Multisig?>>()
    private val accounts = HashMap<PublicKey, AccountState>()
    private val htlcs = HashMap<Hash, HTLC?>()
    private val multisigs = HashMap<Hash, Multisig?>()
    private var transactions = ArrayList<Hash>(maxSeenSizeImpl())

    suspend fun check(): Boolean = mutex.withLock {
        var result = true
        val (txs, map) = steal()
        for (hash in txs)
            if (processImpl(hash, map[hash]!!) != Accepted)
                result = false
        if (result == false)
            logger.warn("Removed ${txs.size - transactions.size} transactions, ${transactions.size} remain in pool")
        result
    }

    suspend fun fill(block: Block) = mutex.withLock {
        val poolSize = sizeImpl()
        var freeBlockSize = min(LedgerDB.state().maxBlockSize, Config.softBlockSizeLimit) - 176
        var i = 0
        while (freeBlockSize > 0 && i < poolSize) {
            val hash = transactions.get(i++)
            val bytes = getImpl(hash)
            if (bytes == null) {
                logger.error("Inconsistent MemPool")
                continue
            }
            if (bytes.size + 4 > freeBlockSize)
                break

            freeBlockSize -= bytes.size + 4
            block.transactions.add(SerializableByteArray(bytes))
        }
    }

    internal fun clearRejectsImpl() {
        rejects.clear()
    }

    suspend fun isInteresting(hash: Hash): Boolean = mutex.withLock {
        return !rejects.contains(hash) && !containsImpl(hash)
    }

    suspend fun getSequence(key: PublicKey): Int = mutex.withLock {
        val account = accounts.get(key)
        if (account != null)
            return account.seq
        return LedgerDB.get(key)?.seq ?: 0
    }

    suspend fun get(hash: Hash): ByteArray? = mutex.withLock {
        return@withLock getImpl(hash)
    }

    override fun addSupply(amount: Long) {}

    override fun checkReferenceChain(hash: Hash): Boolean {
        return LedgerDB.checkReferenceChain(hash)
    }

    override fun checkFee(size: Int, amount: Long): Boolean {
        return amount >= Node.minTxFee * (1 + size / 1000)
    }

    override fun blockTime(): Long {
        return LedgerDB.state().blockTime
    }

    override fun height(): Int {
        return LedgerDB.state().height
    }

    override fun get(key: PublicKey): AccountState? {
        val account = accounts.get(key)
        if (account != null) {
            if (!undoAccounts.containsKey(key))
                undoAccounts.put(key, account.copy())
            return account
        } else {
            val dbAccount = LedgerDB.get(key)
            undoAccounts.put(key, null)
            return dbAccount
        }
    }

    override fun getOrCreate(key: PublicKey): AccountState {
        val account = get(key)
        return if (account != null) {
            account
        } else {
            undoAccounts.put(key, null)
            AccountState.create()
        }
    }

    override fun set(key: PublicKey, state: AccountState) {
        accounts.put(key, state)
    }

    override fun addHTLC(id: Hash, htlc: HTLC) {
        undoHtlcs.put(id, Pair(false, null))
        htlcs.put(id, htlc)
    }

    override fun getHTLC(id: Hash): HTLC? {
        return if (!htlcs.containsKey(id)) {
            undoHtlcs.put(id, Pair(false, null))
            LedgerDB.getHTLC(id)
        } else {
            val htlc = htlcs.get(id)
            undoHtlcs.putIfAbsent(id, Pair(true, htlc))
            htlc
        }
    }

    override fun removeHTLC(id: Hash) {
        htlcs.put(id, null)
    }

    override fun addMultisig(id: Hash, multisig: Multisig) {
        undoMultisigs.put(id, Pair(false, null))
        multisigs.put(id, multisig)
    }

    override fun getMultisig(id: Hash): Multisig? {
        return if (!multisigs.containsKey(id)) {
            undoMultisigs.put(id, Pair(false, null))
            LedgerDB.getMultisig(id)
        } else {
            val multisig = multisigs.get(id)
            undoMultisigs.putIfAbsent(id, Pair(true, multisig))
            multisig
        }
    }

    override fun removeMultisig(id: Hash) {
        multisigs.put(id, null)
    }

    private fun undoImpl(status: Status) {
        if (status != Accepted) {
            undoAccounts.forEach { (key, account) ->
                if (account != null)
                    accounts.put(key, account)
                else
                    accounts.remove(key)
            }
            undoHtlcs.forEach { (id, pair) ->
                val (put, htlc) = pair
                if (put)
                    htlcs.put(id, htlc)
                else
                    htlcs.remove(id)
            }
            undoMultisigs.forEach { (id, pair) ->
                val (put, multisig) = pair
                if (put)
                    multisigs.put(id, multisig)
                else
                    multisigs.remove(id)
            }
        }
        undoAccounts.clear()
        undoHtlcs.clear()
        undoMultisigs.clear()
    }

    private suspend fun processImpl(hash: Hash, bytes: ByteArray): Status {
        val tx = Transaction.deserialize(bytes)
        val status = processTransactionImpl(tx, hash, bytes.size)
        if (status == Accepted) {
            addImpl(hash, bytes)
            transactions.add(hash)
        }
        undoImpl(status)
        return status
    }

    private suspend fun processImplWithFee(hash: Hash, bytes: ByteArray, time: Long): Pair<Status, Long> {
        val tx = Transaction.deserialize(bytes)
        val status = processTransactionImpl(tx, hash, bytes.size)
        if (status == Accepted) {
            addImpl(hash, bytes)
            transactions.add(hash)
            WalletDB.processTransaction(hash, tx, bytes, time)
            APIServer.txPoolNotify(tx, hash, time, bytes.size)
            logger.debug { "Accepted $hash" }
        }
        undoImpl(status)
        return Pair(status, tx.fee)
    }

    suspend fun process(hash: Hash, bytes: ByteArray, time: Long, remote: Boolean): Pair<Status, Long> = mutex.withLock {
        if (rejects.contains(hash))
            return Pair(Invalid("Already rejected tx"), 0)
        if (containsImpl(hash))
            return Pair(AlreadyHave(hash.toString()), 0)
        if (TxPool.dataSizeImpl() + bytes.size > Config.txPoolSize) {
            if (remote)
                return Pair(InFuture("TxPool is full"), 0)
            else
                logger.warn("TxPool is full")
        }
        val result = TxPool.processImplWithFee(hash, bytes, time)
        if (result.first is Invalid || result.first is InFuture) {
            rejects.add(hash)
        }
        return result
    }

    internal suspend fun removeImpl(hashes: List<Hash>) {
        if (hashes.isEmpty() || transactions.isEmpty())
            return

        val (txs, map) = steal()
        for (hash in txs)
            if (!hashes.contains(hash))
                processImpl(hash, map[hash]!!)
    }

    private fun steal(): Pair<ArrayList<Hash>, HashMap<Hash, ByteArray>> {
        val txs = transactions
        val map = stealImpl()
        accounts.clear()
        htlcs.clear()
        multisigs.clear()
        transactions = ArrayList(maxSeenSizeImpl())
        return Pair(txs, map)
    }

    // 复活吗？
}
