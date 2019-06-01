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

@Serializable
class Signature(val bytes: ByteArray) {
    override fun equals(other: Any?): Boolean = (other is Signature) && bytes.contentEquals(other.bytes)
    override fun hashCode(): Int = bytes.contentHashCode()
    override fun toString(): String = bytes.toHex()

    @Serializer(forClass = Signature::class)
    companion object {
        const val SIZE = 64
        val EMPTY = Signature(ByteArray(SIZE))

        fun fromString(hex: String?): Signature? {
            if (hex == null) return null
            val bytes = fromHex(hex, SIZE) ?: return null
            return Signature(bytes)
        }

        override fun deserialize(decoder: Decoder): Signature {
            return when (decoder) {
                is BinaryDecoder -> Signature(decoder.decodeByteArrayValue(SIZE))
                is JsonInput -> Signature.fromString(decoder.decodeString())!!
                else -> throw RuntimeException("unsupported decoder")
            }
        }

        override fun serialize(encoder: Encoder, obj: Signature) {
            when (encoder) {
                is BinaryEncoder -> encoder.encodeByteArrayValue(obj.bytes)
                is JsonOutput -> encoder.encodeString(obj.bytes.toHex())
                else -> throw RuntimeException("unsupported encoder")
            }
        }
    }
}
