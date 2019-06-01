/*
 * Copyright (c) 2018-2019 Pavel Vasin
 * Copyright (c) 2019 Blacknet Team
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.core

import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.withLock
import mu.KotlinLogging
import ninja.blacknet.crypto.*
import ninja.blacknet.db.BlockDB
import ninja.blacknet.db.LedgerDB
import ninja.blacknet.network.ChainFetcher
import ninja.blacknet.network.Node
import ninja.blacknet.util.SynchronizedArrayList
import ninja.blacknet.util.byteArrayOfInts
import ninja.blacknet.util.delay

private val logger = KotlinLogging.logger {}

object PoS {
    fun reward(supply: Long): Long {
        val blocks = 365 * 24 * 60 * 60 / TARGET_BLOCK_TIME
        return supply / 100 / blocks
    }

    fun nxtrng(nxtrng: Hash, generator: PublicKey): Hash {
        return (Blake2b.Hasher() + nxtrng.bytes + generator.bytes).hash()
    }

    fun check(time: Long, generator: PublicKey, nxtrng: Hash, difficulty: BigInt, prevTime: Long, stake: Long): Boolean {
        if (stake <= 0) {
            logger.info("invalid stake amount $stake")
            return false
        }
        if (time and TIMESTAMP_MASK != 0L) {
            logger.info("invalid timestamp mask")
            return false
        }
        val hash = (Blake2b.Hasher() + nxtrng.bytes + prevTime + generator.bytes + time).hash()
        val x = hash.toBigInt() / stake
        return x < difficulty
    }

    fun nextDifficulty(difficulty: BigInt, prevBlockTime: Long, blockTime: Long): BigInt {
        val dTime = Math.min(blockTime - prevBlockTime, TARGET_BLOCK_TIME * SPACING)
        return difficulty * (A2 + 2 * dTime) / A1
    }

    fun cumulativeDifficulty(cumulativeDifficulty: BigInt, difficulty: BigInt): BigInt {
        return cumulativeDifficulty + ONE_SHL_256 / difficulty
    }

    private val stakers = SynchronizedArrayList<Pair<PrivateKey, PublicKey>>()
    internal suspend fun stakersSize() = stakers.size()

    private var job: Job? = null
    private suspend fun miner() {
        while (true) {
            delay(1)

            //XXX race condition
            if (ChainFetcher.isConnectingBlocks())
                continue

            if (Node.isOffline())
                continue

            if (Node.isInitialSynchronization())
                continue

            val time = Node.time() and (TIMESTAMP_MASK xor -1L)
            if (time <= LedgerDB.blockTime())
                continue

            @Suppress("LABEL_NAME_CLASH")
            val block = stakers.mutex.withLock {
                BlockDB.mutex.withLock {
                    for (i in stakers.list.indices) {
                        val privateKey = stakers.list[i].first
                        val publicKey = stakers.list[i].second

                        val stake = LedgerDB.get(publicKey)?.stakingBalance(LedgerDB.height()) ?: 0

                        if (stake > 0 && check(time, publicKey, LedgerDB.nxtrng(), LedgerDB.difficulty(), LedgerDB.blockTime(), stake)) {
                            val block = Block.create(LedgerDB.blockHash(), time, publicKey)
                            TxPool.fill(block)
                            return@withLock block.sign(privateKey)
                        }
                    }
                    return@withLock null
                }
            }

            if (block != null) {
                logger.info("Staked ${block.first}")
                Node.broadcastBlock(block.first, block.second)
            }
        }
    }

    suspend fun startStaking(privateKey: PrivateKey): Boolean = stakers.mutex.withLock {
        val publicKey = privateKey.toPublicKey()

        val pair = Pair(privateKey, publicKey)
        if (stakers.list.contains(pair)) {
            logger.info("${Address.encode(publicKey)} is already staking")
            return false
        }

        if (LedgerDB.get(publicKey) == null)
            logger.warn("${Address.encode(publicKey)} not found in LedgerDB")

        stakers.list.add(pair)
        if (stakers.list.size == 1)
            job = Node.launch { miner() }
        return true
    }

    suspend fun stopStaking(privateKey: PrivateKey): Boolean = stakers.mutex.withLock {
        val publicKey = privateKey.toPublicKey()
        val pair = Pair(privateKey, publicKey)
        if (!stakers.list.remove(pair)) {
            logger.info("${Address.encode(publicKey)} is not staking")
            return false
        }
        if (stakers.list.size == 0) {
            job!!.cancel()
            job = null
        }
        return true
    }

    suspend fun isStaking(privateKey: PrivateKey): Boolean = stakers.mutex.withLock {
        return stakers.list.find { it.first == privateKey } != null
    }

    const val TARGET_BLOCK_TIME = 64L
    const val TARGET_TIMESPAN = 960L
    const val INTERVAL = TARGET_TIMESPAN / TARGET_BLOCK_TIME
    const val SPACING = 10
    const val TIMESTAMP_MASK = 15L
    const val DEFAULT_CONFIRMATIONS = 10
    const val MATURITY = 1350
    const val BLOCK_SIZE_SPAN = 1351
    const val COIN = 100000000L
    const val MIN_LEASE = 1000 * COIN
    val A1 = BigInt((INTERVAL + 1) * TARGET_BLOCK_TIME)
    val A2 = BigInt((INTERVAL - 1) * TARGET_BLOCK_TIME)
    val INITIAL_DIFFICULTY = BigInt(byteArrayOfInts(0x00, 0xAF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF))
    val ONE_SHL_256 = BigInt.ONE shl 256
}
