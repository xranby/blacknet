/*
 * Copyright (c) 2018 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.core

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import ninja.blacknet.crypto.Hash
import ninja.blacknet.network.Connection

abstract class DataDB {
    internal val mutex = Mutex()
    private val TX_INVALID = Pair(Status.INVALID, 0L)
    private val TX_ALREADY_HAVE = Pair(Status.ALREADY_HAVE, 0L)
    private val TX_IN_FUTURE = Pair(Status.IN_FUTURE, 0L)
    private val rejects = HashSet<Hash>()

    internal fun clearRejectsImpl() {
        rejects.clear()
    }

    suspend fun isInteresting(hash: Hash): Boolean = mutex.withLock {
        return !rejects.contains(hash) && !containsImpl(hash)
    }

    suspend fun isRejected(hash: Hash): Boolean = mutex.withLock {
        return rejects.contains(hash)
    }

    suspend fun process(hash: Hash, bytes: ByteArray, connection: Connection? = null): Status = mutex.withLock {
        if (rejects.contains(hash))
            return Status.INVALID
        if (containsImpl(hash))
            return Status.ALREADY_HAVE
        val status = processImpl(hash, bytes, connection)
        if (status == Status.INVALID)
            rejects.add(hash)
        return status
    }

    suspend fun processTx(hash: Hash, bytes: ByteArray, connection: Connection? = null): Pair<Status, Long> = mutex.withLock {
        if (rejects.contains(hash))
            return TX_INVALID
        if (containsImpl(hash))
            return TX_ALREADY_HAVE
        val fee = TxPool.processImplWithFee(hash, bytes, connection)
        if (fee == TxPool.INVALID) {
            rejects.add(hash)
            return TX_INVALID
        } else if (fee == TxPool.IN_FUTURE) {
            rejects.add(hash)
            return TX_IN_FUTURE
        }
        return Pair(Status.ACCEPTED, fee)
    }

    abstract suspend fun get(hash: Hash): ByteArray?
    protected abstract suspend fun containsImpl(hash: Hash): Boolean
    protected abstract suspend fun processImpl(hash: Hash, bytes: ByteArray, connection: Connection?): Status

    enum class Status {
        ACCEPTED,
        IN_FUTURE,
        ALREADY_HAVE,
        INVALID,
        NOT_ON_THIS_CHAIN,
        ;
    }
}
