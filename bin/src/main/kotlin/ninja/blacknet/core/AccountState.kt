/*
 * Copyright (c) 2018 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.core

import kotlinx.serialization.Decoder
import kotlinx.serialization.Encoder
import kotlinx.serialization.Serializable
import kotlinx.serialization.Serializer
import mu.KotlinLogging
import ninja.blacknet.crypto.PublicKey
import ninja.blacknet.serialization.BinaryDecoder
import ninja.blacknet.serialization.BinaryEncoder
import ninja.blacknet.util.sumByLong

private val logger = KotlinLogging.logger {}

@Serializable
class AccountState(
        var seq: Int,
        var stake: Long,
        var immature: MutableList<Input>,
        var leases: MutableList<LeaseInput>
) {
    override fun equals(other: Any?): Boolean {
        return (other is AccountState) && seq == other.seq && stake == other.stake && immature == other.immature && leases == other.leases
    }

    override fun hashCode(): Int {
        return seq xor stake.hashCode() xor immature.hashCode() xor leases.hashCode()
    }

    fun serialize(): ByteArray = BinaryEncoder.toBytes(serializer(), this)

    fun balance(): Long {
        return stake + immature.sumByLong { it.amount }
    }

    fun confirmedBalance(height: Int, confirmations: Int): Long {
        return stake + immature.sumByLong { it.confirmedBalance(height, confirmations) }
    }

    fun stakingBalance(height: Int): Long {
        return stake + immature.sumByLong { it.matureBalance(height) } + leases.sumByLong { it.matureBalance(height) }
    }

    fun totalBalance(): Long {
        return stake + immature.sumByLong { it.amount } + leases.sumByLong { it.amount }
    }

    fun credit(amount: Long): Boolean {
        if (amount < 0) {
            logger.info("negative amount")
            return false
        }

        if (amount <= stake) {
            stake -= amount
            return true
        }

        if (balance() < amount) {
            logger.info("insufficient funds")
            return false
        }

        var r = amount - stake
        stake = 0
        while (r > 0) {
            if (r < immature[0].amount) {
                immature[0].amount -= r
                break
            } else {
                r -= immature[0].amount
                immature.removeAt(0)
            }
        }

        return true
    }

    fun debit(height: Int, amount: Long) {
        if (amount != 0L)
            immature.add(Input(height, amount))
    }

    fun prune(height: Int) {
        if (height < 0) return

        val mature = immature.sumByLong { it.matureBalance(height) }
        if (mature == 0L) return

        stake += mature
        immature = immature.asSequence().filter { !it.isMature(height) }.toMutableList()
    }

    @Serializable
    class Input(val height: Int, var amount: Long) {
        override fun equals(other: Any?): Boolean = (other is Input) && height == other.height && amount == other.amount
        override fun hashCode(): Int = height xor amount.hashCode()
        fun copy(): Input = Input(height, amount)
        fun isConfirmed(height: Int, confirmations: Int): Boolean = height > this.height + confirmations
        fun isMature(height: Int): Boolean = height > this.height + PoS.MATURITY
        fun confirmedBalance(height: Int, confirmations: Int): Long = if (isConfirmed(height, confirmations)) amount else 0
        fun matureBalance(height: Int): Long = if (isMature(height)) amount else 0
    }

    @Serializable
    class LeaseInput(val from: PublicKey, val height: Int, val amount: Long) {
        override fun equals(other: Any?): Boolean = (other is LeaseInput) && from == other.from && height == other.height && amount == other.amount
        override fun hashCode(): Int = from.hashCode() xor height xor amount.hashCode()
        fun isMature(height: Int): Boolean = height > this.height + PoS.MATURITY
        fun matureBalance(height: Int): Long = if (isMature(height)) amount else 0
    }

    fun copy(): AccountState {
        val copyImmature = ArrayList<Input>(immature.size)
        for (i in 0 until immature.size)
            copyImmature.add(immature[i].copy())
        return AccountState(seq, stake, copyImmature, ArrayList(leases))
    }

    fun isEmpty(): Boolean {
        return seq == 0 && stake == 0L && immature.isEmpty() && leases.isEmpty()
    }

    @Serializer(forClass = AccountState::class)
    companion object {
        fun deserialize(bytes: ByteArray): AccountState? = BinaryDecoder.fromBytes(bytes).decode(serializer())

        fun create(stake: Long = 0): AccountState {
            return AccountState(0, stake, ArrayList(), ArrayList())
        }

        override fun deserialize(decoder: Decoder): AccountState {
            when (decoder) {
                is BinaryDecoder -> {
                    val seq = decoder.unpackInt()
                    val stake = decoder.unpackLong()
                    val immatureSize = decoder.unpackInt()
                    val immature = ArrayList<Input>(immatureSize)
                    for (i in 0 until immatureSize)
                        immature.add(Input(decoder.unpackInt(), decoder.unpackLong()))
                    val leasesSize = decoder.unpackInt()
                    val leases = ArrayList<LeaseInput>(leasesSize)
                    for (i in 0 until leasesSize)
                        leases.add(LeaseInput(PublicKey(decoder.decodeByteArrayValue(PublicKey.SIZE)), decoder.unpackInt(), decoder.unpackLong()))
                    return AccountState(seq, stake, immature, leases)
                }
                else -> throw RuntimeException("unsupported decoder")
            }
        }

        override fun serialize(encoder: Encoder, obj: AccountState) {
            when (encoder) {
                is BinaryEncoder -> {
                    encoder.packInt(obj.seq)
                    encoder.packLong(obj.stake)
                    encoder.packInt(obj.immature.size)
                    for (i in 0 until obj.immature.size) {
                        encoder.packInt(obj.immature[i].height)
                        encoder.packLong(obj.immature[i].amount)
                    }
                    encoder.packInt(obj.leases.size)
                    for (i in 0 until obj.leases.size) {
                        encoder.encodeByteArrayValue(obj.leases[i].from.bytes)
                        encoder.packInt(obj.leases[i].height)
                        encoder.packLong(obj.leases[i].amount)
                    }
                }
                else -> throw RuntimeException("unsupported encoder")
            }
        }
    }
}
