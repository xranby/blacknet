/*
 * Copyright (c) 2018 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.core

import kotlinx.serialization.Serializable
import ninja.blacknet.crypto.*
import ninja.blacknet.serialization.BinaryDecoder
import ninja.blacknet.serialization.BinaryEncoder
import ninja.blacknet.serialization.SerializableByteArray

@Serializable
data class HTLC(
        val height: Int,
        val time: Long,
        val amount: Long,
        val from: PublicKey,
        val to: PublicKey,
        val timeLockType: Byte,
        val timeLock: Long,
        val hashType: Byte,
        val hashLock: SerializableByteArray
) {
    fun involves(publicKey: PublicKey): Boolean = from == publicKey || to == publicKey
    fun serialize(): ByteArray = BinaryEncoder.toBytes(serializer(), this)

    fun verifyTimeLock(ledger: Ledger): Boolean {
        val type = TimeLockType.get(timeLockType) ?: return false
        return type.verify(this, ledger)
    }

    fun verifyHashLock(preimage: SerializableByteArray): Boolean {
        val type = HashType.get(hashType) ?: return false
        return type.verify(this, preimage)
    }

    enum class HashType(
            val hash: (ByteArray) -> ByteArray
    ) {
        BLAKE256(ninja.blacknet.crypto.Blake2b),
        SHA256(ninja.blacknet.crypto.SHA256),
        KECCAK256(ninja.blacknet.crypto.Keccak256),
        RIPEMD160(ninja.blacknet.crypto.RIPEMD160),
        ;

        fun verify(htlc: HTLC, preimage: SerializableByteArray): Boolean {
            return hash(preimage.array).contentEquals(htlc.hashLock.array)
        }

        companion object {
            fun get(type: Byte): HashType? = when (type) {
                HashType.BLAKE256.ordinal.toByte() -> BLAKE256
                HashType.SHA256.ordinal.toByte() -> SHA256
                HashType.KECCAK256.ordinal.toByte() -> KECCAK256
                HashType.RIPEMD160.ordinal.toByte() -> RIPEMD160
                else -> null
            }
        }
    }

    enum class TimeLockType(
            val verify: (HTLC, Ledger) -> Boolean
    ) {
        TIME({ htlc, ledger -> htlc.timeLock < ledger.blockTime() }),
        HEIGHT({ htlc, ledger -> htlc.timeLock < ledger.height() }),
        RELATIVE_TIME({ htlc, ledger -> htlc.time + htlc.timeLock < ledger.blockTime() }),
        RELATIBE_HEIGHT({ htlc, ledger -> htlc.height + htlc.timeLock < ledger.height() }),
        ;

        companion object {
            fun get(type: Byte): TimeLockType? = when (type) {
                TimeLockType.TIME.ordinal.toByte() -> TIME
                TimeLockType.HEIGHT.ordinal.toByte() -> HEIGHT
                TimeLockType.RELATIVE_TIME.ordinal.toByte() -> RELATIVE_TIME
                TimeLockType.RELATIBE_HEIGHT.ordinal.toByte() -> RELATIBE_HEIGHT
                else -> null
            }
        }
    }

    companion object {
        fun deserialize(bytes: ByteArray): HTLC? = BinaryDecoder.fromBytes(bytes).decode(HTLC.serializer())

        fun isValidTimeLockType(type: Byte): Boolean = TimeLockType.get(type) != null
        fun isValidHashType(type: Byte): Boolean = HashType.get(type) != null
    }
}
