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
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.withLock
import mu.KotlinLogging
import ninja.blacknet.Config
import ninja.blacknet.Config.mnemonics
import ninja.blacknet.Runtime
import ninja.blacknet.api.StakingInfo
import ninja.blacknet.crypto.*
import ninja.blacknet.db.BlockDB
import ninja.blacknet.db.LedgerDB
import ninja.blacknet.network.Node
import ninja.blacknet.util.SynchronizedArrayList
import ninja.blacknet.util.delay
import ninja.blacknet.util.sumByLong

private val logger = KotlinLogging.logger {}

/**
 * 权益关系器
 */
object Staker /* Holder */ {
    private class StakerState(
            val publicKey: PublicKey,
            val privateKey: PrivateKey
    ) {
        val startTime = Runtime.timeMilli()
        var hashCounter = 0
        var lastBlock = Hash.ZERO
        var stake = 0L

        fun hashRate(): Double {
            val time = Runtime.timeMilli() - startTime
            return if (time != 0L)
                hashCounter.toDouble() / (time / 1000)
            else
                0.0
        }

        fun updateImpl(state: LedgerDB.State) {
            lastBlock = state.blockHash
            stake = LedgerDB.get(publicKey)?.stakingBalance(state.height) ?: 0
        }
    }

    private val stakers = SynchronizedArrayList<StakerState>()

    init {
        if (Config.contains(mnemonics)) {
            runBlocking {
                Config[mnemonics].forEachIndexed { index, mnemonic ->
                    val privateKey = Mnemonic.fromString(mnemonic)
                    if (privateKey != null) {
                        startStaking(privateKey)
                    } else {
                        logger.warn("Invalid mnemonic $index")
                    }
                }
                val n = stakers.list.size
                if (n == 1)
                    logger.info("Started staking")
                else if (n > 1)
                    logger.info("Started staking with $n accounts")
            }
        }
    }

    private var job: Job? = null
    private suspend fun implementation() {
        delay(1)

        if (!Config.regTest) {
            if (Node.isOffline())
                return

            if (Node.isInitialSynchronization())
                return
        }

        var state = LedgerDB.state()
        val currTime = Runtime.time()
        val timeSlot = currTime - currTime % PoS.TIME_SLOT
        if (timeSlot <= state.blockTime)
            return

        stakers.forEach { staker ->
            if (staker.lastBlock != state.blockHash) {
                BlockDB.mutex.withLock {
                    state = LedgerDB.state()
                    staker.updateImpl(state)
                }
            }
            staker.hashCounter += 1
            val pos = PoS.check(timeSlot, staker.publicKey, state.nxtrng, state.difficulty, state.blockTime, staker.stake)
            if (pos == Accepted) {
                val block = Block.create(state.blockHash, timeSlot, staker.publicKey)
                TxPool.fill(block)
                val (hash, bytes) = block.sign(staker.privateKey)
                logger.info("Staked $hash")
                if (Node.broadcastBlock(hash, bytes)) {
                    return
                } else @Suppress("NAME_SHADOWING") {
                    state = LedgerDB.state()
                    if (timeSlot <= state.blockTime)
                        return
                    if (block.transactions.isEmpty())
                        return
                    block.transactions.clear()
                    if (TxPool.check() == false) {
                        TxPool.fill(block)
                        if (block.transactions.isNotEmpty()) {
                            val (hash, bytes) = block.sign(staker.privateKey)
                            logger.warn("Retry $hash")
                            if (Node.broadcastBlock(hash, bytes))
                                return
                            else
                                block.transactions.clear()
                        }
                    }
                    val (hash, bytes) = block.sign(staker.privateKey)
                    logger.warn("Empty $hash")
                    Node.broadcastBlock(hash, bytes)
                }
            }
        }
    }

    suspend fun startStaking(privateKey: PrivateKey): Boolean = stakers.mutex.withLock {
        val publicKey = privateKey.toPublicKey()

        if (stakers.list.find { it.publicKey == publicKey } != null) {
            logger.info("${Address.encode(publicKey)} is already staking")
            return false
        }

        val staker = StakerState(publicKey, privateKey)
        BlockDB.mutex.withLock {
            val state = LedgerDB.state()
            staker.updateImpl(state)
        }
        if (staker.stake == 0L) {
            logger.warn("${Address.encode(publicKey)} has zero staking balance")
        }

        stakers.list.add(staker)
        if (stakers.list.size == 1) {
            job = Runtime.rotate(::implementation)
        }
        return true
    }

    suspend fun stopStaking(privateKey: PrivateKey): Boolean = stakers.mutex.withLock {
        val publicKey = privateKey.toPublicKey()
        val i = stakers.list.indexOfFirst { it.publicKey == publicKey }
        if (i != -1) {
            stakers.list.removeAt(i)
        } else {
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
        return stakers.list.find { it.privateKey == privateKey } != null
    }

    suspend fun info(publicKey: PublicKey?): StakingInfo {
        val (nAccounts, hashRate, weight) = stakers.mutex.withLock {
            if (publicKey == null) {
                Triple(
                        stakers.list.size,
                        stakers.list.sumByDouble { it.hashRate() },
                        stakers.list.sumByLong { it.stake }
                )
            } else {
                val staker = stakers.list.find { it.publicKey == publicKey }
                if (staker != null)
                    Triple(1, staker.hashRate(), staker.stake)
                else
                    Triple(0, 0.0, 0L)
            }
        }
        val state = LedgerDB.state()
        val networkWeight = (PoS.MAX_DIFFICULTY / state.difficulty).toLong() / PoS.TARGET_BLOCK_TIME * PoS.TIME_SLOT
        val expectedTime = if (weight != 0L) PoS.TARGET_BLOCK_TIME * networkWeight / weight else 0L
        return StakingInfo(nAccounts, hashRate, weight.toString(), networkWeight.toString(), expectedTime)
    }
}
