/*
 * Copyright (c) 2018-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.crypto

import java.math.BigInteger
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import ninja.blacknet.serialization.ContextualSerializer
import ninja.blacknet.serialization.bbf.BinaryDecoder
import ninja.blacknet.serialization.bbf.BinaryEncoder
import ninja.blacknet.serialization.notSupportedFormatError
import ninja.blacknet.serialization.descriptor.ListSerialDescriptor

/**
 * Contextual serializer for a [BigInteger].
 */
object BigIntegerSerializer : ContextualSerializer<BigInteger>()

/**
 * Serializes a [BigInteger].
 */
object BigIntegerAsBinarySerializer : KSerializer<BigInteger> {
    override val descriptor: SerialDescriptor = ListSerialDescriptor(
            "ninja.blacknet.crypto.BigIntegerAsBinarySerializer",
            Byte.serializer().descriptor
    )

    override fun deserialize(decoder: Decoder): BigInteger {
        return when (decoder) {
            is BinaryDecoder -> BigInteger(decoder.decodeByteArray())
            else -> throw notSupportedFormatError(decoder, this)
        }
    }

    override fun serialize(encoder: Encoder, value: BigInteger) {
        when (encoder) {
            is BinaryEncoder -> encoder.encodeByteArray(value.toByteArray())
            is HashEncoder -> encoder.encodeByteArray(value.toByteArray())
            else -> throw notSupportedFormatError(encoder, this)
        }
    }
}

/**
 * Serializes a [BigInteger] with a transformation to a decimal string.
 */
object BigIntegerAsStringSerializer : KSerializer<BigInteger> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor(
            "ninja.blacknet.crypto.BigIntegerAsStringSerializer",
            PrimitiveKind.STRING
    )

    override fun deserialize(decoder: Decoder): BigInteger {
        return BigInteger(decoder.decodeString())
    }

    override fun serialize(encoder: Encoder, value: BigInteger) {
        encoder.encodeString(value.toString())
    }
}
