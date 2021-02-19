/*
 * Copyright (c) 2018-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.core

import kotlinx.serialization.Serializable
import ninja.blacknet.crypto.PoS
import ninja.blacknet.crypto.PublicKeySerializer
import ninja.blacknet.crypto.SipHash.hashCode
import ninja.blacknet.serialization.VarIntSerializer
import ninja.blacknet.serialization.VarLongSerializer
import ninja.blacknet.util.sumByLong

@Serializable
class AccountState(
        @Serializable(with = VarIntSerializer::class)
        var seq: Int = 0,
        @Serializable(with = VarLongSerializer::class)
        var stake: Long = 0L,
        var immature: MutableList<Input> = ArrayList(),
        var leases: MutableList<Lease> = ArrayList()
) {
    override fun equals(other: Any?): Boolean {
        return (other is AccountState) && seq == other.seq && stake == other.stake && immature == other.immature && leases == other.leases
    }

    override fun hashCode(): Int {
        return hashCode(serializer(), this)
    }

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
        stake = 0L
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
    class Input(
        @Serializable(with = VarIntSerializer::class)
        val height: Int,
        @Serializable(with = VarLongSerializer::class)
        var amount: Long
    ) {
        override fun equals(other: Any?): Boolean = (other is Input) && height == other.height && amount == other.amount
        override fun hashCode(): Int = hashCode(serializer(), this)
        fun copy(): Input = Input(height, amount)
        fun isConfirmed(height: Int, confirmations: Int): Boolean = height > this.height + confirmations
        fun isMature(height: Int): Boolean = height > this.height + PoS.MATURITY
        fun confirmedBalance(height: Int, confirmations: Int): Long = if (isConfirmed(height, confirmations)) amount else 0L
        fun matureBalance(height: Int): Long = if (isMature(height)) amount else 0L
    }

    @Serializable
    class Lease(
        @Serializable(with = PublicKeySerializer::class)
        val publicKey: ByteArray,
        @Serializable(with = VarIntSerializer::class)
        val height: Int,
        @Serializable(with = VarLongSerializer::class)
        var amount: Long
    ) {
        override fun equals(other: Any?): Boolean = (other is Lease) && publicKey.contentEquals(other.publicKey) && height == other.height && amount == other.amount
        override fun hashCode(): Int = hashCode(serializer(), this)
        fun copy(): Lease = Lease(publicKey, height, amount)
        fun isMature(height: Int): Boolean = height > this.height + PoS.MATURITY
        fun matureBalance(height: Int): Long = if (isMature(height)) amount else 0L
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
}
