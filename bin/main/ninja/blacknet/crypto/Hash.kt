/*
 * Copyright (c) 2018 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.crypto

import kotlinx.serialization.Decoder
import kotlinx.serialization.Encoder
import kotlinx.serialization.Serializable
import kotlinx.serialization.Serializer
import kotlinx.serialization.json.JsonInput
import kotlinx.serialization.json.JsonOutput
import ninja.blacknet.serialization.BinaryDecoder
import ninja.blacknet.serialization.BinaryEncoder
import ninja.blacknet.serialization.fromHex
import ninja.blacknet.serialization.toHex
import java.math.BigInteger

@Serializable
class Hash(val bytes: ByteArray) {
    override fun equals(other: Any?): Boolean = (other is Hash) && bytes.contentEquals(other.bytes)
    override fun hashCode(): Int = bytes.contentHashCode()
    override fun toString(): String = bytes.toHex()

    fun toBigInt(): BigInt = BigInt(BigInteger(1, bytes))

    @Serializer(forClass = Hash::class)
    companion object {
        const val SIZE = 32
        const val DIGEST_SIZE = SIZE * 8
        val ZERO = Hash(ByteArray(SIZE))

        fun fromString(hex: String?): Hash? {
            if (hex == null) return null
            val bytes = fromHex(hex, SIZE) ?: return null
            return Hash(bytes)
        }

        override fun deserialize(decoder: Decoder): Hash {
            return when (decoder) {
                is BinaryDecoder -> Hash(decoder.decodeByteArrayValue(SIZE))
                is JsonInput -> Hash.fromString(decoder.decodeString())!!
                else -> throw RuntimeException("unsupported decoder")
            }
        }

        override fun serialize(encoder: Encoder, obj: Hash) {
            when (encoder) {
                is BinaryEncoder -> encoder.encodeByteArrayValue(obj.bytes)
                is JsonOutput -> encoder.encodeString(obj.bytes.toHex())
                else -> throw RuntimeException("unsupported encoder")
            }
        }
    }
}
