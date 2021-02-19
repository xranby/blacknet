/*
 * Copyright (c) 2018-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.serialization

import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import ninja.blacknet.codec.base.Base16
import ninja.blacknet.crypto.HashEncoder
import ninja.blacknet.crypto.encodeByteArray
import ninja.blacknet.serialization.bbf.BinaryDecoder
import ninja.blacknet.serialization.bbf.BinaryEncoder
import ninja.blacknet.serialization.descriptor.ListSerialDescriptor

/**
 * Contextual serializer for a [ByteArray].
 */
object ByteArraySerializer : ContextualSerializer<ByteArray>()

/**
 * Serializes a [ByteArray].
 */
object ByteArrayAsBinarySerializer : KSerializer<ByteArray> {
    override val descriptor: SerialDescriptor = ListSerialDescriptor(
            "ninja.blacknet.serialization.ByteArrayAsBinarySerializer",
            Byte.serializer().descriptor
    )

    override fun deserialize(decoder: Decoder): ByteArray {
        return when (decoder) {
            is BinaryDecoder -> decoder.decodeByteArray()
            else -> throw notSupportedFormatError(decoder, this)
        }
    }

    override fun serialize(encoder: Encoder, value: ByteArray) {
        when (encoder) {
            is BinaryEncoder -> encoder.encodeByteArray(value)
            is HashEncoder -> encoder.encodeByteArray(value)
            else -> throw notSupportedFormatError(encoder, this)
        }
    }
}

/**
 * Serializes a [ByteArray] with a transformation to a hex string.
 */
object ByteArrayAsStringSerializer : KSerializer<ByteArray> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor(
            "ninja.blacknet.serialization.ByteArrayAsStringSerializer",
            PrimitiveKind.STRING
    )

    override fun deserialize(decoder: Decoder): ByteArray {
        return Base16.decode(decoder.decodeString())
    }

    override fun serialize(encoder: Encoder, value: ByteArray) {
        encoder.encodeString(Base16.encode(value))
    }
}
