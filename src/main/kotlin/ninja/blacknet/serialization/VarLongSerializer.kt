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
import ninja.blacknet.serialization.bbf.*

/**
 * Serializes a [Long] with variable number of bytes in a binary representation.
 */
object VarLongSerializer : KSerializer<Long> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor(
        "ninja.blacknet.serialization.VarLongSerializer",
        PrimitiveKind.LONG  // PrimitiveKind.STRING
    )

    override fun deserialize(decoder: Decoder): Long {
        return when (decoder) {
            is BinaryDecoder -> decoder.decodeVarLong()
            is JsonDecoder -> decoder.decodeString().toLong()
            is RequestDecoder -> decoder.decodeLong()
            else -> throw notSupportedFormatError(decoder, this)
        }
    }

    override fun serialize(encoder: Encoder, value: Long) {
        when (encoder) {
            is BinaryEncoder -> encoder.encodeVarLong(value)
            is HashEncoder -> encoder.encodeLong(value)
            is JsonEncoder -> encoder.encodeString(value.toString())
            else -> throw notSupportedFormatError(encoder, this)
        }
    }
}
