/*
 * Copyright (c) 2018-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.core

import java.math.BigDecimal
import kotlin.math.min
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import mu.KotlinLogging
import ninja.blacknet.Config
import ninja.blacknet.crypto.HashSerializer
import ninja.blacknet.crypto.PoS
import ninja.blacknet.db.LedgerDB
import ninja.blacknet.db.WalletDB
import ninja.blacknet.rpc.RPCServer
import ninja.blacknet.serialization.bbf.binaryFormat
import ninja.blacknet.util.HashMap
import ninja.blacknet.util.HashSet

private val logger = KotlinLogging.logger {}

object TxPool : MemPool(), Ledger {
    internal val mutex = Mutex()
    private val rejects = HashSet<ByteArray>()
    private val undoAccounts = HashMap<ByteArray, AccountState?>()
    private val undoHtlcs = HashMap<ByteArray, Pair<Boolean, HTLC?>>()
    private val undoMultisigs = HashMap<ByteArray, Pair<Boolean, Multisig?>>()
    private val accounts = HashMap<ByteArray, AccountState>()
    private val htlcs = HashMap<ByteArray, HTLC?>()
    private val multisigs = HashMap<ByteArray, Multisig?>()
    private var transactions = ArrayList<ByteArray>(maxSeenSizeImpl())
    internal var minFeeRate = parseAmount(Config.instance.minfeerate)

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
        var freeBlockSize = min(LedgerDB.state().maxBlockSize, Config.instance.softblocksizelimit.bytes) - 176
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
            block.transactions.add(bytes)
        }
    }

    internal fun clearRejectsImpl() {
        rejects.clear()
    }

    suspend fun isInteresting(hash: ByteArray): Boolean = mutex.withLock {
        return !rejects.contains(hash) && !containsImpl(hash)
    }

    suspend fun getSequence(key: ByteArray): Int = mutex.withLock {
        val account = accounts.get(key)
        if (account != null)
            return account.seq
        return LedgerDB.get(key)?.seq ?: 0
    }

    suspend fun get(hash: ByteArray): ByteArray? = mutex.withLock {
        return@withLock getImpl(hash)
    }

    override fun addSupply(amount: Long) {}

    override fun checkReferenceChain(hash: ByteArray): Boolean {
        return LedgerDB.checkReferenceChain(hash)
    }

    override fun checkFee(size: Int, amount: Long): Boolean {
        return amount >= minFeeRate * (1 + size / 1000)
    }

    override fun blockTime(): Long {
        return LedgerDB.state().blockTime
    }

    override fun height(): Int {
        return LedgerDB.state().height
    }

    override fun getAccount(key: ByteArray): AccountState? {
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

    override fun getOrCreate(key: ByteArray): AccountState {
        val account = getAccount(key)
        return if (account != null) {
            account
        } else {
            undoAccounts.put(key, null)
            AccountState()
        }
    }

    override fun setAccount(key: ByteArray, state: AccountState) {
        accounts.put(key, state)
    }

    override fun addHTLC(id: ByteArray, htlc: HTLC) {
        undoHtlcs.put(id, Pair(false, null))
        htlcs.put(id, htlc)
    }

    override fun getHTLC(id: ByteArray): HTLC? {
        return if (!htlcs.containsKey(id)) {
            undoHtlcs.put(id, Pair(false, null))
            LedgerDB.getHTLC(id)
        } else {
            val htlc = htlcs.get(id)
            undoHtlcs.putIfAbsent(id, Pair(true, htlc))
            htlc
        }
    }

    override fun removeHTLC(id: ByteArray) {
        htlcs.put(id, null)
    }

    override fun addMultisig(id: ByteArray, multisig: Multisig) {
        undoMultisigs.put(id, Pair(false, null))
        multisigs.put(id, multisig)
    }

    override fun getMultisig(id: ByteArray): Multisig? {
        return if (!multisigs.containsKey(id)) {
            undoMultisigs.put(id, Pair(false, null))
            LedgerDB.getMultisig(id)
        } else {
            val multisig = multisigs.get(id)
            undoMultisigs.putIfAbsent(id, Pair(true, multisig))
            multisig
        }
    }

    override fun removeMultisig(id: ByteArray) {
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

    private fun processImpl(hash: ByteArray, bytes: ByteArray): Status {
        val tx = binaryFormat.decodeFromByteArray(Transaction.serializer(), bytes)
        val status = processTransactionImpl(tx, hash, bytes.size)
        if (status == Accepted) {
            addImpl(hash, bytes)
            transactions.add(hash)
        }
        undoImpl(status)
        return status
    }

    private suspend fun processImplWithFee(hash: ByteArray, bytes: ByteArray, time: Long): Pair<Status, Long> {
        val tx = binaryFormat.decodeFromByteArray(Transaction.serializer(), bytes)
        val status = processTransactionImpl(tx, hash, bytes.size)
        if (status == Accepted) {
            addImpl(hash, bytes)
            transactions.add(hash)
            WalletDB.processTransaction(hash, tx, bytes, time)
            RPCServer.txPoolNotify(tx, hash, time, bytes.size)
            logger.debug { "Accepted ${HashSerializer.encode(hash)}" }
        }
        undoImpl(status)
        return Pair(status, tx.fee)
    }

    suspend fun process(hash: ByteArray, bytes: ByteArray, time: Long, remote: Boolean): Pair<Status, Long> = mutex.withLock {
        if (rejects.contains(hash))
            return Pair(Invalid("Already rejected tx"), 0)
        if (containsImpl(hash))
            return Pair(AlreadyHave(HashSerializer.encode(hash)), 0)
        if (TxPool.dataSizeImpl() + bytes.size > Config.instance.txpoolsize.bytes) {
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

    internal fun removeImpl(hashes: List<ByteArray>) {
        if (hashes.isEmpty() || transactions.isEmpty())
            return

        val (txs, map) = steal()
        for (hash in txs)
            if (!hashes.contains(hash))
                processImpl(hash, map[hash]!!)
    }

    private fun steal(): Pair<ArrayList<ByteArray>, HashMap<ByteArray, ByteArray>> {
        val txs = transactions
        val map = stealImpl()
        accounts.clear()
        htlcs.clear()
        multisigs.clear()
        transactions = ArrayList(maxSeenSizeImpl())
        return Pair(txs, map)
    }

    private fun parseAmount(string: String): Long {
        val n = (BigDecimal(string) * BigDecimal(PoS.COIN)).longValueExact()
        if (n < 0) throw RuntimeException("Negative amount")
        return n
    }
}
