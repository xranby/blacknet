/*
 * Copyright (c) 2018-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.contract

import com.rfksystems.blake2b.Blake2b.BLAKE2_B_256
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import ninja.blacknet.crypto.HashEncoder.Companion.buildHash
import ninja.blacknet.crypto.encodeByteArray
import ninja.blacknet.serialization.ByteArraySerializer

const val BLAKE256: Byte = 0
const val SHA256: Byte = 1
const val KECCAK256: Byte = 2
const val RIPEMD160: Byte = 3

@Serializable
class HashLock(
        val type: Byte,
        @Serializable(with = ByteArraySerializer::class)
        val data: ByteArray
) {
    fun validate(): Unit {
        if (hashSizeBytes() == data.size)
            Unit
        else
            throw RuntimeException("Expected hash lock size ${hashSizeBytes()} actual ${data.size}")
    }

    fun verify(preimage: ByteArray): Boolean {
        return buildHash(algorithm()) { encodeByteArray(preimage) }.contentEquals(data)
    }

    private fun algorithm(): String = when (type) {
        BLAKE256 -> BLAKE2_B_256
        SHA256 -> "SHA-256"
        KECCAK256 -> "KECCAK-256"
        RIPEMD160 -> "RIPEMD160"
        else -> throw RuntimeException("Unknown hash type $type")
    }

    private fun hashSizeBytes(): Int = when (type) {
        BLAKE256 -> 32
        SHA256 -> 32
        KECCAK256 -> 32
        RIPEMD160 -> 20
        else -> throw RuntimeException("Unknown hash type $type")
    }
}
