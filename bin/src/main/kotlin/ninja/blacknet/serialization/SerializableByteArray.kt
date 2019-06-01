/*
 * Copyright (c) 2018 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.serialization

import kotlinx.serialization.Decoder
import kotlinx.serialization.Encoder
import kotlinx.serialization.Serializable
import kotlinx.serialization.Serializer
import kotlinx.serialization.json.JsonInput
import kotlinx.serialization.json.JsonOutput

@Serializable
class SerializableByteArray(
        val array: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        return (other is SerializableByteArray) && array.contentEquals(other.array)
    }

    override fun hashCode(): Int {
        return array.contentHashCode()
    }

    override fun toString(): String {
        return array.toHex()
    }

    @Serializer(forClass = SerializableByteArray::class)
    companion object {
        val EMPTY = SerializableByteArray(ByteArray(0))

        fun fromString(hex: String?): SerializableByteArray? {
            if (hex == null) return null
            val bytes = fromHex(hex) ?: return null
            return SerializableByteArray(bytes)
        }

        override fun deserialize(decoder: Decoder): SerializableByteArray {
            return when (decoder) {
                is BinaryDecoder -> decoder.decodeSerializableByteArrayValue()
                is JsonInput -> fromString(decoder.decodeString())!!
                else -> throw RuntimeException("unsupported decoder")
            }
        }

        override fun serialize(encoder: Encoder, obj: SerializableByteArray) {
            when (encoder) {
                is BinaryEncoder -> encoder.encodeSerializableByteArrayValue(obj)
                is JsonOutput -> encoder.encodeString(obj.array.toHex())
                else -> throw RuntimeException("unsupported encoder")
            }
        }
    }
}
