/*
 * Copyright (c) 2018-2020 Pavel Vasin
 * Copyright (c) 2019 Blacknet Team
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.network

import java.math.BigInteger
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ClosedSendChannelException
import kotlinx.coroutines.sync.withLock
import mu.KotlinLogging
import ninja.blacknet.Runtime
import ninja.blacknet.core.*
import ninja.blacknet.crypto.HashSerializer
import ninja.blacknet.crypto.PoS
import ninja.blacknet.db.BlockDB
import ninja.blacknet.db.LedgerDB
import ninja.blacknet.network.packet.Blocks
import ninja.blacknet.network.packet.ChainAnnounce
import ninja.blacknet.network.packet.ChainFork
import ninja.blacknet.network.packet.GetBlocks
import ninja.blacknet.network.packet.PacketType

private val logger = KotlinLogging.logger {}

/**
 * 區塊鏈獲取器
 */
object ChainFetcher {
    private val announces = Channel<Pair<Connection, ChainAnnounce>?>(16)
    private val deferChannel = Channel<Pair<Blocks, BigInteger>>(16)
    private val recvChannel = Channel<Blocks>(Channel.RENDEZVOUS)
    @Volatile
    private var request: Deferred<Blocks>? = null
    private var connectedBlocks = 0
    @Volatile
    private var stakedBlock: Triple<ByteArray, ByteArray, CompletableDeferred<Pair<Status, Int>>>? = null
    @Volatile
    private var syncConnection: Connection? = null
    private var originalChain: ByteArray? = null
    private var rollbackTo: ByteArray? = null
    private var undoDifficulty = BigInteger.ZERO
    private var undoRollback: List<ByteArray>? = null

    private val coroutine = Runtime.rotate(::implementation)

    fun run(): Nothing = runBlocking {
        coroutine.join()
        throw RuntimeException("ChainFetcher exited")
    }

    fun isSynchronizing(): Boolean {
        return syncConnection != null
    }

    fun disconnected(connection: Connection) {
        if (syncConnection != connection)
            return

        request?.cancel(CancellationException("Connection closed"))
    }

    fun offer(connection: Connection, announce: ChainAnnounce) {
        if (announce.cumulativeDifficulty <= LedgerDB.state().cumulativeDifficulty)
            return

        announces.offer(Pair(connection, announce))
    }

    suspend fun stakedBlock(hash: ByteArray, bytes: ByteArray): Pair<Status, Int> {
        val deferred = CompletableDeferred<Pair<Status, Int>>()
        stakedBlock = Triple(hash, bytes, deferred)
        request?.cancel(CancellationException("Staked new block"))
        announces.offer(null)
        return deferred.await()
    }

    private suspend fun implementation() {
        val data = announces.receive()

        stakedBlock?.let { (hash, bytes, deferred) ->
            val status = BlockDB.mutex.withLock {
                BlockDB.processImpl(hash, bytes)
            }
            val n = when (status) {
                Accepted -> Node.announceChain(hash, LedgerDB.state().cumulativeDifficulty)
                else -> 0
            }

            stakedBlock = null
            deferred.complete(Pair(status, n))
        }

        deferChannel.poll()?.let { (blocks, requestedDifficulty) ->
            if (requestedDifficulty <= LedgerDB.state().cumulativeDifficulty)
                return@let

            if (blocks.blocks.isNotEmpty()) {
                logger.debug { "Skipped ${blocks.blocks.size} blocks" }
            } else if (blocks.hashes.isNotEmpty()) {
                logger.debug { "Skipped ${blocks.hashes.size} hashes" }
            } else {
                logger.error("Invalid packet Blocks")
            }
        }

        if (data == null)
            return

        val (connection, announce) = data

        if (connection.requestedBlocks) {
            return
        }

        var state = LedgerDB.state()
        if (announce.cumulativeDifficulty <= state.cumulativeDifficulty)
            return

        BlockDB.mutex.withLock {
            if (BlockDB.isRejectedImpl(announce.chain)) {
                connection.dos("Rejected chain")
                return
            }

            logger.info("Fetching ${HashSerializer.encode(announce.chain)}")
            syncConnection = connection
            originalChain = state.blockHash

            try {
                requestBlocks(connection, state.blockHash, state.rollingCheckpoint, announce.cumulativeDifficulty)

                requestLoop@ while (true) {
                    val answer = withTimeout(timeout()) {
                        request!!.await()
                    }
                    if (answer.blocks.isNotEmpty()) {
                        val accepted = processBlocks(connection, answer)
                        if (!accepted)
                            break

                        state = LedgerDB.state()

                        if (announce.cumulativeDifficulty > state.cumulativeDifficulty) {
                            requestBlocks(connection, state.blockHash, state.rollingCheckpoint, announce.cumulativeDifficulty)
                        } else {
                            break
                        }
                    } else if (answer.hashes.isNotEmpty()) {
                        if (rollbackTo != null || connectedBlocks != 0) {
                            connection.dos("Unexpected rollback")
                            break
                        }
                        var prev = state.rollingCheckpoint
                        for (hash in answer.hashes) {
                            if (BlockDB.isRejectedImpl(hash)) {
                                connection.dos("Rejected chain")
                                break@requestLoop
                            }
                            val chainIndex = LedgerDB.getChainIndex(hash)
                            if (chainIndex == null)
                                break
                            if (chainIndex.height < state.height - PoS.MATURITY) {
                                connection.dos("Rollback to ${chainIndex.height}")
                                break@requestLoop
                            }
                            prev = hash
                        }
                        rollbackTo = prev
                        requestBlocks(connection, prev, state.rollingCheckpoint, announce.cumulativeDifficulty)
                    } else {
                        break
                    }
                }
            } catch (e: ClosedSendChannelException) {
            } catch (e: TimeoutCancellationException) {
                connection.dos("Fetching cancelled: ${e.message}")
            } catch (e: CancellationException) {
                logger.info("Fetching cancelled: ${e.message}")
            } catch (e: Throwable) {
                logger.error("Exception in processBlocks ${connection.debugName()}", e)
                connection.close()
            }

            undoRollback?.let {
                if (undoDifficulty >= state.cumulativeDifficulty) {
                    logger.info("Reconnecting ${it.size} blocks")
                    val toRemove = LedgerDB.undoRollbackImpl(rollbackTo!!, it)
                    BlockDB.removeImpl(toRemove)
                } else {
                    logger.debug { "Removing ${it.size} blocks from db" }
                    BlockDB.removeImpl(it)
                }
                undoRollback = null
            }
        }

        state = LedgerDB.state()
        if (!state.blockHash.contentEquals(originalChain!!)) {
            Node.announceChain(state.blockHash, state.cumulativeDifficulty, connection)
            connection.lastBlockTime = connection.lastPacketTime
        }

        if (connection.isClosed())
            logger.info("Fetched $connectedBlocks blocks from disconnected ${connection.debugName()}")
        else
            logger.info("Fetched $connectedBlocks blocks from ${connection.debugName()}")

        recvChannel.poll()
        request?.let {
            it.cancel()
            request = null
        }
        syncConnection = null
        connectedBlocks = 0
        originalChain = null
        rollbackTo = null
        undoDifficulty = BigInteger.ZERO
    }

    @Suppress("UNUSED_PARAMETER")
    fun chainFork(connection: Connection, chainFork: ChainFork) {
        if (!connection.requestedBlocks) {
            connection.dos("Unexpected packet ChainFork")
            return
        }

        connection.close()

        if (syncConnection != connection)
            return

        request?.cancel(CancellationException("Fork longer than the rolling checkpoint"))
    }

    suspend fun blocks(connection: Connection, blocks: Blocks) {
        val requestedDifficulty = connection.requestedDifficulty.also {
            connection.requestedDifficulty = BigInteger.ZERO
        }

        if (requestedDifficulty == BigInteger.ZERO) {
            connection.dos("Unexpected packet Blocks")
            return
        }

        if (request == null || syncConnection != connection) {
            deferChannel.send(Pair(blocks, requestedDifficulty))
            announces.offer(null)
            logger.debug { "Deferred packet Blocks from ${connection.debugName()}" }
            return
        }

        recvChannel.send(blocks)
    }

    private suspend fun processBlocks(connection: Connection, answer: Blocks): Boolean {
        if (rollbackTo != null && undoRollback == null) {
            undoDifficulty = LedgerDB.state().cumulativeDifficulty
            undoRollback = LedgerDB.rollbackToImpl(rollbackTo!!)
            logger.info("Disconnected ${undoRollback!!.size} blocks")
        }
        for (i in answer.blocks) {
            val hash = Block.hash(i)
            if (undoRollback?.contains(hash) == true) {
                connection.dos("Rollback contains ${HashSerializer.encode(hash)}")
                return false
            }
            val status = BlockDB.processImpl(hash, i)
            if (status != Accepted) {
                connection.dos(status.toString())
                return false
            }
        }
        if (undoRollback == null)
            LedgerDB.pruneImpl()
        connectedBlocks += answer.blocks.size
        if (answer.blocks.size >= 10)
            logger.info("Connected ${answer.blocks.size} blocks")
        return true
    }

    private fun requestBlocks(
            connection: Connection,
            hash: ByteArray,
            checkpoint: ByteArray,
            difficulty: BigInteger,
    ) {
        request = Runtime.async { recvChannel.receive() }
        connection.requestedDifficulty = difficulty
        // 緊湊型區塊轉發
        connection.sendPacket(PacketType.GetBlocks, GetBlocks(hash, checkpoint))
    }

    private fun timeout(): Long {
        return if (!PoS.guessInitialSynchronization())
            4 * 1000
        else
            10 * 1000
    }
}
