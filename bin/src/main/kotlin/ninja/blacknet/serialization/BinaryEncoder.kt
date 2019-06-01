/*
 * Copyright (c) 2018 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 *
 * packInt, packLong originally come from MapDB http://www.mapdb.org/
 * licensed under the Apache License, Version 2.0
 */

package ninja.blacknet.serialization

import kotlinx.io.core.BytePacketBuilder
import kotlinx.io.core.ByteReadPacket
import kotlinx.io.core.readBytes
import kotlinx.serialization.*
import kotlinx.serialization.internal.EnumDescriptor
import kotlin.experimental.and
import kotlin.experimental.or

class BinaryEncoder : ElementValueEncoder() {
    private val out = BytePacketBuilder()

    fun build(): ByteReadPacket {
        return out.build()
    }

    fun toBytes(): ByteArray {
        return build().readBytes()
    }

    override fun encodeByte(value: Byte) = out.writeByte(value)
    override fun encodeInt(value: Int) = out.writeInt(value)
    override fun encodeLong(value: Long) = out.writeLong(value)

    override fun encodeString(value: String) {
        val bytes = value.toByteArray()
        packInt(bytes.size)
        out.writeFully(bytes, 0, bytes.size)
    }

    override fun encodeEnum(enumDescription: EnumDescriptor, ordinal: Int) = packInt(ordinal)

    override fun beginCollection(desc: SerialDescriptor, collectionSize: Int, vararg typeParams: KSerializer<*>): CompositeEncoder {
        return super.beginCollection(desc, collectionSize, *typeParams).also {
            packInt(collectionSize)
        }
    }

    fun encodeSerializableByteArrayValue(value: SerializableByteArray) {
        packInt(value.array.size)
        out.writeFully(value.array, 0, value.array.size)
    }

    fun encodeByteArrayValue(value: ByteArray) {
        out.writeFully(value, 0, value.size)
    }

    fun packInt(value: Int) {
        var shift = 31 - Integer.numberOfLeadingZeros(value)
        shift -= shift % 7 // round down to nearest multiple of 7
        while (shift != 0) {
            out.writeByte(value.ushr(shift).toByte() and 0x7F)
            shift -= 7
        }
        out.writeByte(value.toByte() and 0x7F or 0x80.toByte())
    }

    fun packLong(value: Long) {
        var shift = 63 - Long.numberOfLeadingZeros(value)
        shift -= shift % 7 // round down to nearest multiple of 7
        while (shift != 0) {
            out.writeByte(value.ushr(shift).toByte() and 0x7F)
            shift -= 7
        }
        out.writeByte(value.toByte() and 0x7F or 0x80.toByte())
    }

    companion object {
        fun <T : Any?> toBytes(strategy: SerializationStrategy<T>, obj: T): ByteArray {
            val encoder = BinaryEncoder()
            strategy.serialize(encoder, obj)
            return encoder.toBytes()
        }

        fun <T : Any?> toPacket(strategy: SerializationStrategy<T>, obj: T): ByteReadPacket {
            val encoder = BinaryEncoder()
            strategy.serialize(encoder, obj)
            return encoder.build()
        }
    }
}

private fun Long.Companion.numberOfLeadingZeros(value: Long): Int = java.lang.Long.numberOfLeadingZeros(value)
