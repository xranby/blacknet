/*
 * Copyright (c) 2018-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.transaction

import kotlinx.serialization.Serializable
import ninja.blacknet.contract.MultiSignatureLockContractIdSerializer
import ninja.blacknet.core.*
import ninja.blacknet.crypto.*
import ninja.blacknet.crypto.Blake2b.buildHash
import ninja.blacknet.serialization.bbf.binaryFormat
import ninja.blacknet.serialization.LongSerializer
import ninja.blacknet.util.HashMap
import ninja.blacknet.util.sumByLong

/**
 * 花費合約
 */
@Serializable
class SpendMultisig(
        @Serializable(with = MultiSignatureLockContractIdSerializer::class)
        val id: ByteArray,
        val amounts: ArrayList<@Serializable(LongSerializer::class) Long>,
        val signatures: ArrayList<SignatureElement>
) : TxData {
    @Serializable
    class SignatureElement(
            val index: Byte,
            @Serializable(with = SignatureSerializer::class)
            val signature: ByteArray
    ) {
        operator fun component1() = index
        operator fun component2() = signature
    }

    fun sign(i: Int, privateKey: ByteArray): Boolean {
        val signature = Ed25519.sign(hash(), privateKey)
        signatures.add(SignatureElement(i.toByte(), signature))
        return true
    }

    private fun verifySignatures(multisig: Multisig, sender: ByteArray): Status {
        val multisigHash = hash()
        val unsigned = HashMap<Byte, ByteArray>(multisig.deposits.size)
        for (i in 0 until multisig.deposits.size) {
            unsigned.put(i.toByte(), multisig.deposits[i].from)
        }

        for ((index, signature) in signatures) {
            val publicKey = unsigned.remove(index)
            if (publicKey == null)
                return Invalid("Invalid or twice signed index $index")
            if (!Ed25519.verify(signature, multisigHash, publicKey))
                return Invalid("Invalid signature at index $index")
        }

        return if (unsigned.containsValue(sender))
            Accepted
        else
            Invalid("Invalid sender")
    }

    private fun hash(): ByteArray {
        val copy = SpendMultisig(id, amounts, ArrayList())
        val bytes = binaryFormat.encodeToByteArray(serializer(), copy)
        return buildHash { encodeByteArray(bytes) }
    }

    override fun processImpl(tx: Transaction, hash: ByteArray, dataIndex: Int, ledger: Ledger): Status {
        val multisig = ledger.getMultisig(id)
        if (multisig == null) {
            return Invalid("Multisig not found")
        }
        if (amounts.size != multisig.deposits.size) {
            return Invalid("Invalid number of amounts")
        }
        val amount = try {
            amounts.sumByLong()
        } catch (e: ArithmeticException) {
            return Invalid("Invalid total amount: ${e.message}")
        }
        if (amount != multisig.amount()) {
            return Invalid("Invalid total amount")
        }
        if (signatures.size + 1 < multisig.n) {
            return Invalid("Invalid number of signatures")
        }
        val status = verifySignatures(multisig, tx.from)
        if (status != Accepted) {
            return status
        }

        val height = ledger.height()

        for (index in 0 until multisig.deposits.size) {
            if (amounts[index] < 0) {
                return Invalid("Negative amount index $index")
            } else if (amounts[index] != 0L) {
                val publicKey = multisig.deposits[index].from
                val toAccount = ledger.getOrCreate(publicKey)
                toAccount.debit(height, amounts[index])
                ledger.setAccount(publicKey, toAccount)
            }
        }

        ledger.removeMultisig(id)
        return Accepted
    }

    fun involves(ids: Set<ByteArray>) = ids.contains(id)
}
