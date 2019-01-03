/*
 * Copyright (c) 2018 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.core

import mu.KotlinLogging
import ninja.blacknet.crypto.*
import ninja.blacknet.db.LedgerDB
import ninja.blacknet.network.Node
import ninja.blacknet.util.SynchronizedHashSet
import ninja.blacknet.util.byteArrayOfInts
import ninja.blacknet.util.delay

private val logger = KotlinLogging.logger {}

object PoS {
    fun reward(supply: Long): Long {
        val blocks = 365 * 24 * 60 * 60 / TARGET_BLOCK_TIME
        return supply / 100 / blocks
    }

    fun nxtrng(nxtrng: Hash, generator: PublicKey): Hash {
        return (Blake2b.Hasher() + nxtrng.bytes.array + generator.bytes.array).hash()
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
        val hash = (Blake2b.Hasher() + nxtrng.bytes.array + prevTime + generator.bytes.array + time).hash()
        val x = hash.toBigInt() / stake
        //println("$hash ${x.toHex()} $difficulty $stake ${x - difficulty}")
        return x < difficulty
    }

    fun nextDifficulty(difficulty: BigInt, prevBlockTime: Long, blockTime: Long): BigInt {
        val dTime = Math.min(blockTime - prevBlockTime, TARGET_BLOCK_TIME * SPACING)
        return difficulty * (A2 + 2 * dTime) / A1
    }

    fun cumulativeDifficulty(cumulativeDifficulty: BigInt, difficulty: BigInt): BigInt {
        return cumulativeDifficulty + ONE_SHL_256 / difficulty
    }

    private val stakers = SynchronizedHashSet<PublicKey>()
    suspend fun staker(privateKey: PrivateKey, publicKey: PublicKey) {
        if (!stakers.add(publicKey)) {
            logger.info("${Address.encode(publicKey)} is already staking")
            return
        }

        while (true) {
            delay(1)
            
            if (Node.isOffline())
                continue

            if (Node.isSynchronizing())
                continue

            val time = Node.time() and (TIMESTAMP_MASK xor -1L)
            if (time <= LedgerDB.blockTime())
                continue

            val stake = LedgerDB.get(publicKey)!!.stakingBalance(LedgerDB.height())
            if (stake <= 0) {
                delay(16)
                continue
            }

            if (check(time, publicKey, LedgerDB.nxtrng(), LedgerDB.difficulty(), LedgerDB.blockTime(), stake)) {
                val block = Block.create(LedgerDB.blockHash(), time, publicKey)
                TxPool.fill(block)
                val signed = block.sign(privateKey)
                Node.broadcastBlock(signed.first, signed.second)
            }
        }
    }

    const val TARGET_BLOCK_TIME = 64L
    const val TARGET_TIMESPAN = 960L
    const val INTERVAL = TARGET_TIMESPAN / TARGET_BLOCK_TIME
    const val SPACING = 10
    const val TIMESTAMP_MASK = 15L
    const val MATURITY = 1350
    const val BLOCK_SIZE_SPAN = 1351
    const val COIN = 100000000L
    const val MIN_LEASE = 1000 * COIN
    val A1 = BigInt((INTERVAL + 1) * TARGET_BLOCK_TIME)
    val A2 = BigInt((INTERVAL - 1) * TARGET_BLOCK_TIME)
    val INITIAL_DIFFICULTY = BigInt(byteArrayOfInts(0x00, 0xAF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF))
    val ONE_SHL_256 = BigInt.ONE shl 256
}
