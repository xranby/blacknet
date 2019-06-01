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
class PublicKey(val bytes: ByteArray) {
    override fun equals(other: Any?): Boolean = (other is PublicKey) && bytes.contentEquals(other.bytes)
    override fun hashCode(): Int = bytes.contentHashCode()
    override fun toString(): String = bytes.toHex()

    fun hash(): Hash = Blake2b.hash(bytes)

    @Serializer(forClass = PublicKey::class)
    companion object {
        const val SIZE = 32

        fun fromString(hex: String?): PublicKey? {
            if (hex == null) return null
            val bytes = fromHex(hex, SIZE) ?: return null
            return PublicKey(bytes)
        }

        override fun deserialize(decoder: Decoder): PublicKey {
            return when (decoder) {
                is BinaryDecoder -> PublicKey(decoder.decodeByteArrayValue(SIZE))
                is JsonInput -> Address.decode(decoder.decodeString())!!
                else -> throw RuntimeException("unsupported decoder")
            }
        }

        override fun serialize(encoder: Encoder, obj: PublicKey) {
            when (encoder) {
                is BinaryEncoder -> encoder.encodeByteArrayValue(obj.bytes)
                is JsonOutput -> encoder.encodeString(Address.encode(obj))
                else -> throw RuntimeException("unsupported encoder")
            }
        }
    }
}
