/*
 * Copyright (c) 2018 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.core

import kotlinx.coroutines.sync.withLock
import mu.KotlinLogging
import ninja.blacknet.crypto.BigInt
import ninja.blacknet.crypto.Hash
import ninja.blacknet.crypto.PublicKey
import ninja.blacknet.db.LedgerDB
import ninja.blacknet.db.WalletDB
import ninja.blacknet.network.Connection
import ninja.blacknet.network.Node
import ninja.blacknet.serialization.SerializableByteArray
import ninja.blacknet.util.SynchronizedArrayList
import ninja.blacknet.util.SynchronizedHashMap

private val logger = KotlinLogging.logger {}

object TxPool : MemPool(), Ledger {
    internal const val INVALID = -1L
    internal const val IN_FUTURE = -2L
    private val accounts = SynchronizedHashMap<PublicKey, AccountState>()
    private val transactions = SynchronizedArrayList<Hash>()

    suspend fun fill(block: Block) = mutex.withLock {
        val poolSize = size()
        var freeSize = LedgerDB.maxBlockSize() - 176
        var i = 0
        while (freeSize > 0 && i < poolSize) {
            val hash = transactions.get(i)
            i++
            val bytes = get(hash)
            if (bytes == null) {
                logger.error("inconsistent mempool")
                continue
            }
            if (bytes.size + 4 > freeSize)
                break

            freeSize -= bytes.size + 4
            block.transactions.add(SerializableByteArray(bytes))
        }
    }

    suspend fun getSequence(key: PublicKey): Int {
        val account = accounts.get(key)
        if (account != null)
            return account.seq
        return LedgerDB.get(key)?.seq ?: 0
    }

    override fun checkBlockHash(hash: Hash): Boolean {
        return LedgerDB.checkBlockHash(hash)
    }

    override fun checkFee(size: Int, amount: Long): Boolean {
        return amount >= Node.minTxFee * (1 + size / 1000)
    }

    override suspend fun get(key: PublicKey): AccountState? {
        val account = accounts.get(key)
        if (account != null)
            return account
        return LedgerDB.get(key)
    }

    override suspend fun set(key: PublicKey, state: AccountState) {
        accounts.put(key, state)
    }

    override suspend fun processImpl(hash: Hash, bytes: ByteArray, connection: Connection?): Status {
        val tx = Transaction.deserialize(bytes)
        if (tx == null) {
            logger.info("deserialization failed")
            return Status.INVALID
        }
        if (processTransactionImpl(tx, hash, bytes.size, TxUndoBuilder())) {
            add(hash, bytes)
            transactions.add(hash)
            val currTime = connection?.lastPacketTime ?: Node.time()
            connection?.lastTxTime = currTime
            WalletDB.processTransaction(hash, tx, bytes, currTime, 0)
            return Status.ACCEPTED
        }
        return Status.INVALID
    }

    internal suspend fun processImplWithFee(hash: Hash, bytes: ByteArray, connection: Connection?): Long {
        val tx = Transaction.deserialize(bytes)
        if (tx == null) {
            logger.info("deserialization failed")
            return INVALID
        }

        val from = LedgerDB.get(tx.from)
        if (from != null)
            if (tx.seq > from.seq)
                return IN_FUTURE
            else if (tx.seq < from.seq)
                return INVALID

        if (processTransactionImpl(tx, hash, bytes.size, TxUndoBuilder())) {
            add(hash, bytes)
            transactions.add(hash)
            val currTime = connection?.lastPacketTime ?: Node.time()
            connection?.lastTxTime = currTime
            WalletDB.processTransaction(hash, tx, bytes, currTime, 0)
            return tx.fee
        }
        return INVALID
    }

    private class TxUndoBuilder : UndoBuilder(0, BigInt.ZERO, BigInt.ZERO, 0, Hash.ZERO, Hash.ZERO, 0, ArrayList()) {
        override fun add(publicKey: PublicKey, state: AccountState) {}
        override fun addHTLC(id: Hash, htlc: HTLC?) {}
        override fun addMultisig(id: Hash, multisig: Multisig?) {}
    }

    internal suspend fun removeImpl(hashes: ArrayList<Hash>) {
        val txs = transactions.copy()
        val map = copy()
        accounts.clear()
        transactions.clear()
        clear()
        for (hash in txs)
            if (!hashes.contains(hash))
                processImpl(hash, map[hash]!!, null)
    }

    override fun addSupply(amount: Long) {}
    override fun addUndo(hash: Hash, undo: UndoBlock) {}
    override fun blockTime() = -1L
    override fun height() = -1
    override fun addHTLC(id: Hash, htlc: HTLC) {}
    override fun getHTLC(id: Hash): HTLC? = null
    override fun removeHTLC(id: Hash) {}
    override fun addMultisig(id: Hash, multisig: Multisig) {}
    override fun getMultisig(id: Hash): Multisig? = null
    override fun removeMultisig(id: Hash) {}
}
