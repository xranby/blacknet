/*
 * Copyright (c) 2018-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.crypto

import java.math.BigInteger
import kotlin.math.min
import ninja.blacknet.core.Accepted
import ninja.blacknet.core.Invalid
import ninja.blacknet.core.Status
import ninja.blacknet.core.currentTimeSeconds
import ninja.blacknet.crypto.Blake2b.buildHash
import ninja.blacknet.db.LedgerDB
import ninja.blacknet.db.LedgerDB.forkV2
import ninja.blacknet.util.byteArrayOfInts

object PoS {
    fun mint(supply: Long): Long {
        return supply / 100 / BLOCKS_IN_YEAR
    }

    fun nxtrng(nxtrng: ByteArray, generator: ByteArray): ByteArray {
        return buildHash {
            encodeByteArray(nxtrng)
            encodeByteArray(generator)
        }
    }

    fun check(time: Long, generator: ByteArray, nxtrng: ByteArray, difficulty: BigInteger, prevTime: Long, stake: Long): Status {
        if (stake <= 0) {
            return Invalid("Invalid stake amount")
        }
        if (time % TIME_SLOT != 0L) {
            return Invalid("Invalid time slot")
        }
        val hash = buildHash {
            encodeByteArray(nxtrng)
            encodeLong(prevTime)
            encodeByteArray(generator)
            encodeLong(time)
        }
        return if (BigInteger(1, hash) < difficulty * stake)
            Accepted
        else
            Invalid("Proof of stake doesn't match difficulty")
    }

    fun isTooFarInFuture(time: Long): Boolean {
        return time >= currentTimeSeconds() + TIME_SLOT
    }

    fun nextDifficulty(difficulty: BigInteger, prevBlockTime: Long, blockTime: Long): BigInteger {
        val dTime = min(blockTime - prevBlockTime, TARGET_BLOCK_TIME * SPACING)
        return difficulty * (A2 + 2 * dTime) / A1
    }

    fun cumulativeDifficulty(cumulativeDifficulty: BigInteger, difficulty: BigInteger): BigInteger {
        return cumulativeDifficulty + ONE_SHL_256 / difficulty
    }

    fun guessInitialSynchronization(): Boolean {
        return currentTimeSeconds() > LedgerDB.state().blockTime + TARGET_BLOCK_TIME * MATURITY
    }

    fun maxBlockSize(blockSizes: Collection<Int>): Int {
        return if (blockSizes.size == BLOCK_SIZE_SPAN) {
            val iterator = blockSizes.iterator()
            val sizes = Array(BLOCK_SIZE_SPAN) { iterator.next() }
            sizes.sort()
            val median = sizes[BLOCK_SIZE_SPAN / 2]
            val size = median * 2
            if (size < 0 || size > MAX_BLOCK_SIZE)
                MAX_BLOCK_SIZE
            else if (size < DEFAULT_MAX_BLOCK_SIZE)
                DEFAULT_MAX_BLOCK_SIZE
            else
                size
        } else {
            DEFAULT_MAX_BLOCK_SIZE
        }
    }

    /**
     * Length of time slot
     */
    val TIME_SLOT get() = if (forkV2()) 4L else 16L
    /**
     * Expected block time
     */
    val TARGET_BLOCK_TIME get() = 4 * TIME_SLOT
    /**
     * Expected number of blocks in year
     */
    val BLOCKS_IN_YEAR get() = 365 * 24 * 60 * 60 / TARGET_BLOCK_TIME
    /**
     * Default number of confirmations
     */
    const val DEFAULT_CONFIRMATIONS = 10
    /**
     * Maximum number of blocks that can be rolled back
     */
    const val MATURITY = 1350
    /**
     * Number of blocks used to calculate the maximum block size
     */
    const val BLOCK_SIZE_SPAN = 1351
    /**
     * Satoshi
     */
    const val COIN = 100000000L
    /**
     * Minimum amount that can be leased out for cold staking
     */
    const val MIN_LEASE = 1000 * COIN
    /**
     * Difficulty of genesis block
     */
    val INITIAL_DIFFICULTY = BigInteger(byteArrayOfInts(0x00, 0xAF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF))
    /**
     * Maximum value of difficulty
     */
    val MAX_DIFFICULTY = BigInteger(byteArrayOfInts(0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF))
    /**
     * Reserved from maximum block size
     */
    const val BLOCK_RESERVED_SIZE = 100
    /**
     * Minimum maximum block size
     */
    const val DEFAULT_MAX_BLOCK_SIZE = 100000
    /**
     * Maximum block size
     */
    const val MAX_BLOCK_SIZE = Int.MAX_VALUE - BLOCK_RESERVED_SIZE

    private const val INTERVAL = 15
    private const val SPACING = 10
    private val A1 get() = (INTERVAL + 1) * TARGET_BLOCK_TIME
    private val A2 get() = (INTERVAL - 1) * TARGET_BLOCK_TIME
    private val ONE_SHL_256 = BigInteger.ONE shl 256

    /**
     * 高精度整數乘法
     */
    @Suppress("NOTHING_TO_INLINE")
    private inline operator fun BigInteger.times(other: Long): BigInteger = multiply(BigInteger.valueOf(other))
    /**
     * 高精度整數除法
     */
    @Suppress("NOTHING_TO_INLINE")
    private inline operator fun BigInteger.div(other: Long): BigInteger = divide(BigInteger.valueOf(other))
}

/*
 * History of changes
 *
 * Version 4:
 * Switched to accounts
 * Added cold staking
 * Added dynamic block size
 *
 * Version 3:
 * Switched to NXTRNG
 * Removed coin age
 * Added rolling checkpoint
 */
