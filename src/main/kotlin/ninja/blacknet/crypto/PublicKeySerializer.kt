/*
 * Copyright (c) 2018-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.crypto

import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import ninja.blacknet.codec.base.HexCodecException
import ninja.blacknet.serialization.ContextualSerializer
import ninja.blacknet.serialization.bbf.BinaryDecoder
import ninja.blacknet.serialization.bbf.BinaryEncoder
import ninja.blacknet.serialization.notSupportedFormatError
import ninja.blacknet.serialization.descriptor.ListSerialDescriptor

/**
 * Contextual serializer for an Ed25519 public key.
 */
object PublicKeySerializer : ContextualSerializer<ByteArray>() {
    /**
     * The number of bytes in a binary representation of the public key.
     */
    const val SIZE_BYTES = 32

    fun decode(string: String): ByteArray {
        return try {
            decodeHex(string, SIZE_BYTES * 2)
        } catch (e: HexCodecException) {
            Address.decode(string)
        }
    }
}

/**
 * Serializes an Ed25519 public key.
 */
object PublicKeyAsBinarySerializer : KSerializer<ByteArray> {
    override val descriptor: SerialDescriptor = ListSerialDescriptor(
            "ninja.blacknet.crypto.PublicKeyAsBinarySerializer",
            Byte.serializer().descriptor
    )

    override fun deserialize(decoder: Decoder): ByteArray {
        return when (decoder) {
            is BinaryDecoder -> decoder.decodeFixedByteArray(PublicKeySerializer.SIZE_BYTES)
            else -> throw notSupportedFormatError(decoder, this)
        }
    }

    override fun serialize(encoder: Encoder, value: ByteArray) {
        when (encoder) {
            is BinaryEncoder -> encoder.encodeFixedByteArray(value)
            is HashEncoder -> encoder.encodeByteArray(value)
            else -> throw notSupportedFormatError(encoder, this)
        }
    }
}

/**
 * Serializes an Ed25519 public key.
 */
object PublicKeyAsStringSerializer : KSerializer<ByteArray> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor(
            "ninja.blacknet.crypto.PublicKeyAsStringSerializer",
            PrimitiveKind.STRING
    )

    override fun deserialize(decoder: Decoder): ByteArray {
        return PublicKeySerializer.decode(decoder.decodeString())
    }

    override fun serialize(encoder: Encoder, value: ByteArray) {
        encoder.encodeString(Address.encode(value))
    }
}
