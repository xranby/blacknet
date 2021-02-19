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
import ninja.blacknet.core.*
import ninja.blacknet.crypto.*
import ninja.blacknet.crypto.Blake2b.buildHash
import ninja.blacknet.serialization.bbf.binaryFormat
import ninja.blacknet.serialization.LongSerializer
import ninja.blacknet.util.sumByLong

/**
 * 創建合約
 */
@Serializable
class CreateMultisig(
        val n: Byte,
        val deposits: ArrayList<DepositElement>,
        val signatures: ArrayList<SignatureElement>
) : TxData {
    @Serializable
    class DepositElement(
            @Serializable(with = PublicKeySerializer::class)
            val from: ByteArray,
            @Serializable(with = LongSerializer::class)
            val amount: Long
    ) {
        operator fun component1() = from
        operator fun component2() = amount
    }

    @Serializable
    class SignatureElement(
            val index: Byte,
            @Serializable(with = SignatureSerializer::class)
            val signature: ByteArray
    ) {
        operator fun component1() = index
        operator fun component2() = signature
    }

    fun id(hash: ByteArray, dataIndex: Int): ByteArray =
        buildHash {
            encodeByteArray(hash);
            encodeInt(dataIndex);
        }

    fun sign(from: ByteArray, seq: Int, dataIndex: Int, privateKey: ByteArray): Boolean {
        val publicKey = Ed25519.toPublicKey(privateKey)
        val index = deposits.indexOfFirst { it.from.contentEquals(publicKey) }
        if (index == -1) return false
        val signature = Ed25519.sign(hash(from, seq, dataIndex), privateKey)
        signatures.add(SignatureElement(index.toByte(), signature))
        return true
    }

    private fun hash(from: ByteArray, seq: Int, dataIndex: Int): ByteArray {
        val copy = CreateMultisig(n, deposits, ArrayList())
        val bytes = binaryFormat.encodeToByteArray(serializer(), copy)
        return buildHash {
            encodeByteArray(from)
            encodeInt(seq)
            encodeInt(dataIndex)
            encodeByteArray(bytes)
        }
    }

    override fun processImpl(tx: Transaction, hash: ByteArray, dataIndex: Int, ledger: Ledger): Status {
        if (n < 0 || n > deposits.size) {
            return Invalid("Invalid n")
        }
        if (deposits.size > 20) {
            return Invalid("Too many deposits")
        }
        if (signatures.size > deposits.size) {
            return Invalid("Too many signatures")
        }
        val total = try {
            deposits.sumByLong { it.amount }
        } catch (e: ArithmeticException) {
            return Invalid("Invalid total amount: ${e.message}")
        }
        if (total <= 0) {
            return Invalid("Invalid total amount")
        }

        val multisigHash = hash(tx.from, tx.seq, dataIndex)
        for (index in 0 until deposits.size) {
            val (publicKey, amount) = deposits[index]
            if (amount != 0L) {
                val signature = signatures.find { it.index == index.toByte() }?.signature
                if (signature == null) {
                    return Invalid("Unsigned deposit $index")
                }
                if (!Ed25519.verify(signature, multisigHash, publicKey)) {
                    return Invalid("Invalid signature $index")
                }
                val depositAccount = ledger.getAccount(publicKey)
                if (depositAccount == null) {
                    return Invalid("Account not found $index")
                }
                val status = depositAccount.credit(amount)
                if (status != Accepted) {
                    return notAccepted("CreateMultisig at index $index", status)
                }
                ledger.setAccount(publicKey, depositAccount)
            }
        }

        val id = id(hash, dataIndex)
        val multisig = Multisig(n, deposits.map { (from, amount) -> Multisig.DepositElement(from, amount) })
        ledger.addMultisig(id, multisig)
        return Accepted
    }

    fun involves(publicKey: ByteArray) = deposits.find { it.from.contentEquals(publicKey) } != null
}
