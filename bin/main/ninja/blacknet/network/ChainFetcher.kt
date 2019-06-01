/*
 * Copyright (c) 2018-2019 Pavel Vasin
 * Copyright (c) 2019 Blacknet Team
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.network

import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ClosedSendChannelException
import mu.KotlinLogging
import ninja.blacknet.core.Block
import ninja.blacknet.core.DataDB.Status
import ninja.blacknet.core.PoS
import ninja.blacknet.crypto.BigInt
import ninja.blacknet.crypto.Hash
import ninja.blacknet.db.BlockDB
import ninja.blacknet.db.LedgerDB
import ninja.blacknet.util.withTimeout

private val logger = KotlinLogging.logger {}

object ChainFetcher {
    const val TIMEOUT = 5
    private val chains = Channel<ChainData>(16)
    private val recvChannel = Channel<Blocks>(Channel.RENDEZVOUS)
    @Volatile
    private var request: Deferred<Blocks>? = null
    private var connectedBlocks = 0
    @Volatile
    private var connectingBlocks = false
    @Volatile
    private var syncChain: ChainData? = null
    private var originalChain: Hash? = null
    private var rollbackTo: Hash? = null
    private var undoDifficulty = BigInt.ZERO
    private var undoRollback: ArrayList<Hash>? = null

    init {
        Node.launch { fetcher() }
    }

    fun isConnectingBlocks(): Boolean {
        return connectingBlocks
    }

    fun isSynchronizing(): Boolean {
        return syncChain != null
    }

    internal fun disconnected(connection: Connection) {
        if (syncChain?.connection == connection)
            request?.cancel(CancellationException("Connection closed"))
    }

    fun offer(connection: Connection, chain: Hash, cumulativeDifficulty: BigInt? = null) {
        if (chain == Hash.ZERO)
            return
        if (cumulativeDifficulty != null && cumulativeDifficulty <= LedgerDB.cumulativeDifficulty())
            return

        chains.offer(ChainData(connection, chain, cumulativeDifficulty))
    }

    private suspend fun fetcher() {
        while (true) {
            val data = chains.receive()

            if (data.connection.isClosed())
                continue
            if (data.cumulativeDifficulty() != BigInt.ZERO && data.cumulativeDifficulty() <= LedgerDB.cumulativeDifficulty())
                continue
            if (!BlockDB.isInteresting(data.chain))
                continue

            logger.info("Fetching ${data.chain} from ${data.connection.remoteAddress}")
            syncChain = data
            originalChain = LedgerDB.blockHash()

            try {
                requestBlocks(data.connection, originalChain!!, LedgerDB.rollingCheckpoint())

                requestLoop@ while (true) {
                    val answer = withTimeout(TIMEOUT) {
                        request!!.await()
                    }
                    if (answer.isEmpty()) {
                        break
                    }
                    if (!answer.hashes.isEmpty()) {
                        if (rollbackTo != null) {
                            data.connection.dos("unexpected rollback")
                            break
                        }
                        val checkpoint = LedgerDB.rollingCheckpoint()
                        var prev = checkpoint
                        for (hash in answer.hashes) {
                            if (BlockDB.isRejected(hash)) {
                                data.connection.dos("invalid chain")
                                break@requestLoop
                            }
                            val blockNumber = LedgerDB.getBlockNumber(hash)
                            if (blockNumber == null)
                                break
                            if (blockNumber < LedgerDB.height() - PoS.MATURITY - 1) {
                                data.connection.dos("rollback to $blockNumber")
                                break@requestLoop
                            }
                            prev = hash
                        }
                        rollbackTo = prev
                        requestBlocks(data.connection, prev, checkpoint)
                        continue
                    }
                    connectingBlocks = true
                    val accepted = processBlocks(data.connection, answer)
                    connectingBlocks = false
                    if (!accepted)
                        break

                    if (data.chain == LedgerDB.blockHash()) {
                        break
                    } else {
                        if (data.cumulativeDifficulty() == BigInt.ZERO
                                || data.cumulativeDifficulty() > LedgerDB.cumulativeDifficulty()) {
                            requestBlocks(data.connection, LedgerDB.blockHash(), LedgerDB.rollingCheckpoint())
                            continue
                        } else {
                            break
                        }
                    }
                }
            } catch (e: ClosedSendChannelException) {
            } catch (e: CancellationException) {
                logger.info("${e.message}")
                data.connection.close()
            } catch (e: Throwable) {
                logger.error("Exception in processBlocks ${data.connection.remoteAddress}", e)
                data.connection.close()
            }

            fetched()
        }
    }

    private suspend fun fetched() {
        val cumulativeDifficulty = LedgerDB.cumulativeDifficulty()
        if (undoRollback != null) {
            if (undoDifficulty >= cumulativeDifficulty) {
                connectingBlocks = true
                logger.info("Reconnecting ${undoRollback!!.size} blocks")
                val toRemove = LedgerDB.undoRollback(rollbackTo!!, undoRollback!!)
                BlockDB.remove(toRemove)
                connectingBlocks = false
            } else {
                logger.debug { "Removing ${undoRollback!!.size} blocks from db" }
                BlockDB.remove(undoRollback!!)
            }
        }

        val newChain = LedgerDB.blockHash()
        if (newChain != originalChain) {
            Node.announceChain(newChain, cumulativeDifficulty, syncChain!!.connection)
        }

        if (syncChain!!.connection.isClosed())
            logger.info("Peer disconnected. Fetched $connectedBlocks blocks")
        else
            logger.info("Finished fetching $connectedBlocks blocks")

        recvChannel.poll()
        if (request != null) {
            request!!.cancel()
            request = null
        }
        syncChain = null
        connectedBlocks = 0
        originalChain = null
        rollbackTo = null
        undoRollback = null
        undoDifficulty = BigInt.ZERO
    }

    fun chainFork(connection: Connection) {
        if (request == null || syncChain == null || syncChain!!.connection != connection) {
            logger.info("Unexpected chain fork message ${connection.remoteAddress}")
            connection.close()
        } else {
            request!!.cancel()
            logger.info("Fork longer than the rolling checkpoint")
        }
    }

    suspend fun fetched(connection: Connection, blocks: Blocks) {
        if (request == null || syncChain == null || syncChain!!.connection != connection) {
            logger.info("Unexpected synchronization ${connection.remoteAddress}")
            connection.close()
            return
        }
        recvChannel.send(blocks)
    }

    private suspend fun processBlocks(connection: Connection, answer: Blocks): Boolean {
        if (rollbackTo != null && undoRollback == null) {
            undoDifficulty = LedgerDB.cumulativeDifficulty()
            undoRollback = LedgerDB.rollbackTo(rollbackTo!!)
            logger.info("Disconnected ${undoRollback!!.size} blocks")
        }
        for (i in answer.blocks) {
            val hash = Block.Hasher(i.array)
            if (undoRollback?.contains(hash) == true) {
                logger.info("Rollback contains $hash")
                connection.close()
                return false
            }
            val status = BlockDB.process(hash, i.array, null)
            if (status == Status.IN_FUTURE) {
                return false
            } else if (status == Status.NOT_ON_THIS_CHAIN) {
                connection.close()
                return false
            } else if (status != Status.ACCEPTED && status != Status.ALREADY_HAVE) {
                logger.info("$status block $hash")
                connection.close()
                return false
            }
        }
        if (undoRollback == null)
            LedgerDB.prune()
        connection.lastBlockTime = Node.time()
        connectedBlocks += answer.blocks.size
        if (answer.blocks.size >= 10)
            logger.info("Connected ${answer.blocks.size} blocks")
        return true
    }

    private fun requestBlocks(connection: Connection, hash: Hash, checkpoint: Hash) {
        request = Node.async { recvChannel.receive() }
        connection.sendPacket(GetBlocks(hash, checkpoint))
    }

    private class ChainData(val connection: Connection, val chain: Hash, val cumulativeDifficulty: BigInt?) {
        fun cumulativeDifficulty() = cumulativeDifficulty ?: BigInt.ZERO
    }
}
