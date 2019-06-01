/*
 * Copyright (c) 2018 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.db

import kotlinx.coroutines.sync.withLock
import mu.KotlinLogging
import ninja.blacknet.api.APIServer
import ninja.blacknet.core.Block
import ninja.blacknet.core.DataDB
import ninja.blacknet.crypto.Hash
import ninja.blacknet.network.Connection
import ninja.blacknet.network.Node

private val logger = KotlinLogging.logger {}

object BlockDB : DataDB() {
    private val BLOCK_KEY = "block".toByteArray()

    suspend fun block(hash: Hash): Pair<Block, Int>? {
        val bytes = get(hash) ?: return null
        val block = Block.deserialize(bytes)
        if (block == null) {
            logger.error("$hash deserialization failed")
            return null
        }
        return Pair(block, bytes.size)
    }

    suspend fun remove(list: ArrayList<Hash>) = mutex.withLock {
        val txDb = LevelDB.createWriteBatch()
        list.forEach {
            txDb.delete(BLOCK_KEY, it.bytes)
        }
        txDb.write()
    }

    override suspend fun containsImpl(hash: Hash): Boolean {
        return LedgerDB.chainContains(hash)
    }

    override suspend fun get(hash: Hash): ByteArray? {
        return LevelDB.get(BLOCK_KEY, hash.bytes)
    }

    override suspend fun processImpl(hash: Hash, bytes: ByteArray, connection: Connection?): Status {
        val block = Block.deserialize(bytes)
        if (block == null) {
            logger.info("deserialization failed")
            return Status.INVALID
        }
        if (block.version != 0 && block.version != 1) {
            logger.info("unknown version ${block.version}")
        }
        if (Node.isTooFarInFuture(block.time)) {
            logger.info("too far in future ${block.time}")
            return Status.IN_FUTURE
        }
        if (!block.verifyContentHash(bytes)) {
            logger.info("invalid content hash")
            return Status.INVALID
        }
        if (!block.verifySignature(hash)) {
            logger.info("invalid signature")
            return Status.INVALID
        }
        LedgerDB.mutex.withLock {
            if (block.previous != LedgerDB.blockHash()) {
                if (connection == null)
                    logger.info("block $hash not on current chain prev ${block.previous}")
                return Status.NOT_ON_THIS_CHAIN
            }
            val batch = LevelDB.createWriteBatch()
            val txDb = LedgerDB.Update(batch, hash, block.time, bytes.size, block.generator)
            if (LedgerDB.processBlockImpl(txDb, hash, block, bytes.size)) {
                batch.put(BLOCK_KEY, hash.bytes, bytes)
                txDb.commitImpl()
                if (connection != null) {
                    logger.info("Accepted block $hash")
                    connection.lastBlockTime = Node.time()
                    Node.announceChain(hash, LedgerDB.cumulativeDifficulty(), connection)
                }
                APIServer.blockNotify(block, hash, LedgerDB.height(), bytes.size)
                return Status.ACCEPTED
            } else {
                batch.close()
                return Status.INVALID
            }
        }
    }
}
