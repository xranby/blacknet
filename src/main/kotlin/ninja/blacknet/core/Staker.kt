/*
 * Copyright (c) 2018-2020 Pavel Vasin
 * Copyright (c) 2019 Blacknet Team
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.core

import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.withLock
import mu.KotlinLogging
import ninja.blacknet.regtest
import ninja.blacknet.Config
import ninja.blacknet.Runtime
import ninja.blacknet.crypto.*
import ninja.blacknet.db.BlockDB
import ninja.blacknet.db.LedgerDB
import ninja.blacknet.network.Node
import ninja.blacknet.rpc.v2.StakingInfo
import ninja.blacknet.util.SynchronizedArrayList
import ninja.blacknet.util.sumByLong

private val logger = KotlinLogging.logger {}

/**
 * 權益采塊器
 */
object Staker {
    private class StakerState(
            val publicKey: ByteArray,
            val privateKey: ByteArray
    ) {
        val startTime = currentTimeMillis()
        var hashCounter = 0
        var lastBlock = HashSerializer.ZERO
        var stake = 0L

        fun hashRate(): Double {
            val time = currentTimeMillis() - startTime
            return if (time != 0L)
                hashCounter.toDouble() / (time / 1000L)
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
        Config.instance.mnemonics?.let { mnemonics ->
            runBlocking {
                mnemonics.forEach { mnemonic ->
                    val privateKey = mnemonic
                    startStaking(privateKey)
                }
                val n = stakers.list.size
                if (n == 1)
                    logger.info("Started staking")
                else if (n > 1)
                    logger.info("Started staking with $n accounts")
                Config.instance.mnemonics = null
            }
        }
    }

    @Volatile
    var awaitsNextTimeSlot: Job? = null
    private var coroutine: Job? = null
    private suspend fun implementation() {
        val job = Runtime.launch {
            val currTime = currentTimeSeconds()
            val nextTimeSlot = currTime - currTime % PoS.TIME_SLOT + PoS.TIME_SLOT
            delay(nextTimeSlot * 1000L - currentTimeMillis())
        }
        awaitsNextTimeSlot = job
        job.join()
        awaitsNextTimeSlot = null

        if (!regtest) {
            if (Node.isOffline())
                return

            if (Node.isInitialSynchronization())
                return
        }

        var state = LedgerDB.state()
        val currTime = currentTimeSeconds()
        val timeSlot = currTime - currTime % PoS.TIME_SLOT
        if (timeSlot <= state.blockTime)
            return

        stakers.forEach { staker ->
            if (!staker.lastBlock.contentEquals(state.blockHash)) {
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
                logger.info("Staked ${HashSerializer.encode(hash)}")
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
                            logger.warn("Retry ${HashSerializer.encode(hash)}")
                            if (Node.broadcastBlock(hash, bytes))
                                return
                            else
                                block.transactions.clear()
                        }
                    }
                    val (hash, bytes) = block.sign(staker.privateKey)
                    logger.warn("Empty ${HashSerializer.encode(hash)}")
                    Node.broadcastBlock(hash, bytes)
                }
            }
        }
    }

    suspend fun startStaking(privateKey: ByteArray): Boolean = stakers.mutex.withLock {
        val publicKey = Ed25519.toPublicKey(privateKey)

        if (stakers.list.find { it.publicKey.contentEquals(publicKey) } != null) {
            logger.info("Stakeholder is already active")
            return false
        }

        val staker = StakerState(publicKey, privateKey)
        BlockDB.mutex.withLock {
            val state = LedgerDB.state()
            staker.updateImpl(state)
        }
        if (staker.stake == 0L) {
            logger.warn("Stakeholder has zero active balance")
        }

        stakers.list.add(staker)
        if (stakers.list.size == 1) {
            coroutine = Runtime.rotate(::implementation)
        }
        return true
    }

    suspend fun stopStaking(privateKey: ByteArray): Boolean = stakers.mutex.withLock {
        val publicKey = Ed25519.toPublicKey(privateKey)
        val i = stakers.list.indexOfFirst { it.publicKey.contentEquals(publicKey) }
        if (i != -1) {
            stakers.list.removeAt(i)
        } else {
            logger.info("Stakeholder is not active")
            return false
        }
        if (stakers.list.size == 0) {
            coroutine!!.cancel()
            coroutine = null
            awaitsNextTimeSlot = null
        }
        return true
    }

    suspend fun isStaking(privateKey: ByteArray): Boolean = stakers.mutex.withLock {
        return stakers.list.find { it.privateKey.contentEquals(privateKey) } != null
    }

    suspend fun info(publicKey: ByteArray?): StakingInfo {
        val (nAccounts, hashRate, weight) = stakers.mutex.withLock {
            if (publicKey == null) {
                Triple(
                        stakers.list.size,
                        stakers.list.sumByDouble { it.hashRate() },
                        stakers.list.sumByLong { it.stake }
                )
            } else {
                val staker = stakers.list.find { it.publicKey.contentEquals(publicKey) }
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
