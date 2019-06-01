/*
 * Copyright (c) 2018 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.transaction

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.jsonArray
import mu.KotlinLogging
import ninja.blacknet.core.*
import ninja.blacknet.crypto.*
import ninja.blacknet.serialization.BinaryEncoder
import ninja.blacknet.serialization.Json
import ninja.blacknet.util.sumByLong

private val logger = KotlinLogging.logger {}

@Serializable
class CreateMultisig(
        val n: Byte,
        val deposits: ArrayList<Pair<PublicKey, Long>>,
        val signatures: ArrayList<Pair<Byte, Signature>>
) : TxData {
    override fun getType() = TxType.CreateMultisig
    override fun involves(publicKey: PublicKey) = deposits.find { it.first == publicKey } != null
    override fun serialize() = BinaryEncoder.toBytes(serializer(), this)
    override fun toJson() = Json.toJson(Info.serializer(), Info(this))

    fun sign(from: PublicKey, seq: Int, privateKey: PrivateKey): Boolean {
        val publicKey = privateKey.toPublicKey()
        val i = deposits.indexOfFirst { it.first == publicKey }
        if (i == -1) return false
        val signature = Ed25519.sign(hash(from, seq), privateKey)
        signatures.add(Pair(i.toByte(), signature))
        return true
    }

    fun verifySignature(signature: Signature, hash: Hash, publicKey: PublicKey): Boolean {
        return Ed25519.verify(signature, hash, publicKey)
    }

    private fun hash(from: PublicKey, seq: Int): Hash {
        val copy = CreateMultisig(n, deposits, ArrayList())
        val bytes = copy.serialize()
        return (Blake2b.Hasher() + from.bytes + seq + bytes).hash()
    }

    override suspend fun processImpl(tx: Transaction, hash: Hash, ledger: Ledger, undo: UndoBuilder): Boolean {
        if (n < 0 || n > deposits.size) {
            logger.info("invalid n")
            return false
        }
        if (deposits.size > 20) {
            logger.info("too many deposits")
            return false
        }
        if (signatures.size > deposits.size) {
            logger.info("too many signatures")
            return false
        }
        val total = try {
            deposits.sumByLong { it.second }
        } catch (e: ArithmeticException) {
            logger.info("invalid total amount: ${e.message}")
            return false
        }
        if (total <= 0) {
            logger.info("invalid total amount")
            return false
        }

        val multisigHash = hash(tx.from, tx.seq)
        for (i in deposits.indices) {
            if (deposits[i].second != 0L) {
                val signature = signatures.find { it.first == i.toByte() }?.second
                if (signature == null) {
                    logger.info("unsigned deposit")
                    return false
                }
                if (!verifySignature(signature, multisigHash, deposits[i].first)) {
                    logger.info("invalid signature")
                    return false
                }
                val depositAccount = ledger.get(deposits[i].first)
                if (depositAccount == null) {
                    logger.info("account not found")
                    return false
                }
                undo.add(deposits[i].first, depositAccount)
                if (!depositAccount.credit(deposits[i].second))
                    return false
                ledger.set(deposits[i].first, depositAccount)
            }
        }

        undo.addMultisig(hash, null)

        val keys = ArrayList<PublicKey>(deposits.size)
        deposits.mapTo(keys) { it.first }
        val multisig = Multisig(total, n, keys)
        ledger.addMultisig(hash, multisig)
        return true
    }

    @Suppress("unused")
    @Serializable
    class Info(
            val n: Int,
            val deposits: JsonArray,
            val signatures: ArrayList<Pair<Byte, Signature>>
    ) {
        constructor(data: CreateMultisig) : this(
                data.n.toUByte().toInt(),
                jsonArray {
                    data.deposits.forEach {
                        Pair(Address.encode(it.first), it.second.toString())
                    }
                },
                data.signatures
        )
    }
}
