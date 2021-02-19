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
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonEncoder
import ninja.blacknet.crypto.HashEncoder
import ninja.blacknet.rpc.requests.RequestDecoder
import ninja.blacknet.serialization.bbf.BinaryDecoder
import ninja.blacknet.serialization.bbf.BinaryEncoder

/**
 * Serializes a [Long] with a transformation to a string in a json representation.
 */
object LongSerializer : KSerializer<Long> {
    /**
     * The number of bytes in a binary representation of a [Long].
     */
    const val SIZE_BYTES = Long.SIZE_BYTES

    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor(
        "ninja.blacknet.serialization.LongSerializer",
        PrimitiveKind.LONG  // PrimitiveKind.STRING
    )

    override fun deserialize(decoder: Decoder): Long {
        return when (decoder) {
            is BinaryDecoder,
            is RequestDecoder,
                -> decoder.decodeLong()
            is JsonDecoder,
                -> decoder.decodeString().toLong()
            else
                -> throw notSupportedFormatError(decoder, this)
        }
    }

    override fun serialize(encoder: Encoder, value: Long) {
        when (encoder) {
            is BinaryEncoder,
            is HashEncoder,
                -> encoder.encodeLong(value)
            is JsonEncoder,
                -> encoder.encodeString(value.toString())
            else
                -> throw notSupportedFormatError(encoder, this)
        }
    }
}
