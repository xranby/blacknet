/*
 * Copyright (c) 2018-2019 Pavel Vasin
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
import ninja.blacknet.crypto.PoS
import ninja.blacknet.crypto.PublicKey
import ninja.blacknet.serialization.BinaryDecoder
import ninja.blacknet.serialization.BinaryEncoder
import ninja.blacknet.util.sumByLong

@Serializable
class AccountState(
        var seq: Int,
        var stake: Long,
        var immature: MutableList<Input>,
        var leases: MutableList<Lease>
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

    fun credit(amount: Long): Status {
        if (amount < 0) {
            return Invalid("Negative amount")
        }

        if (amount <= stake) {
            stake -= amount
            return Accepted
        }

        if (balance() < amount) {
            return Invalid("Insufficient funds")
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

        return Accepted
    }

    fun debit(height: Int, amount: Long) {
        if (amount != 0L)
            immature.add(Input(height, amount))
    }

    fun prune(height: Int): Boolean {
        val mature = immature.sumByLong { it.matureBalance(height) }
        return if (mature == 0L) {
            false
        } else {
            stake += mature
            immature = immature.asSequence().filter { !it.isMature(height) }.toMutableList()
            true
        }
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
    class Lease(val publicKey: PublicKey, var height: Int, var amount: Long) {
        override fun equals(other: Any?): Boolean = (other is Lease) && publicKey == other.publicKey && height == other.height && amount == other.amount
        override fun hashCode(): Int = publicKey.hashCode() xor height xor amount.hashCode()
        fun copy(): Lease = Lease(publicKey, height, amount)
        fun isMature(height: Int): Boolean = height > this.height + PoS.MATURITY
        fun matureBalance(height: Int): Long = if (isMature(height)) amount else 0
    }

    fun copy(): AccountState {
        val copyImmature = ArrayList<Input>(immature.size)
        for (i in 0 until immature.size)
            copyImmature.add(immature[i].copy())
        val copyLeases = ArrayList<Lease>(leases.size)
        for (i in 0 until leases.size)
            copyLeases.add(leases[i].copy())
        return AccountState(seq, stake, copyImmature, copyLeases)
    }

    @Serializer(forClass = AccountState::class)
    companion object {
        fun deserialize(bytes: ByteArray): AccountState = BinaryDecoder.fromBytes(bytes).decode(serializer())

        fun create(stake: Long = 0): AccountState {
            return AccountState(0, stake, ArrayList(), ArrayList())
        }

        override fun deserialize(decoder: Decoder): AccountState {
            when (decoder) {
                is BinaryDecoder -> {
                    val seq = decoder.decodeVarInt()
                    val stake = decoder.decodeVarLong()
                    val immatureSize = decoder.decodeVarInt()
                    val immature = ArrayList<Input>(immatureSize)
                    for (i in 0 until immatureSize)
                        immature.add(Input(decoder.decodeVarInt(), decoder.decodeVarLong()))
                    val leasesSize = decoder.decodeVarInt()
                    val leases = ArrayList<Lease>(leasesSize)
                    for (i in 0 until leasesSize)
                        leases.add(Lease(PublicKey(decoder.decodeFixedByteArray(PublicKey.SIZE)), decoder.decodeVarInt(), decoder.decodeVarLong()))
                    return AccountState(seq, stake, immature, leases)
                }
                else -> throw RuntimeException("Unsupported decoder")
            }
        }

        override fun serialize(encoder: Encoder, obj: AccountState) {
            when (encoder) {
                is BinaryEncoder -> {
                    encoder.encodeVarInt(obj.seq)
                    encoder.encodeVarLong(obj.stake)
                    encoder.encodeVarInt(obj.immature.size)
                    for (i in 0 until obj.immature.size) {
                        encoder.encodeVarInt(obj.immature[i].height)
                        encoder.encodeVarLong(obj.immature[i].amount)
                    }
                    encoder.encodeVarInt(obj.leases.size)
                    for (i in 0 until obj.leases.size) {
                        encoder.encodeFixedByteArray(obj.leases[i].publicKey.bytes)
                        encoder.encodeVarInt(obj.leases[i].height)
                        encoder.encodeVarLong(obj.leases[i].amount)
                    }
                }
                else -> throw RuntimeException("Unsupported encoder")
            }
        }
    }
}
