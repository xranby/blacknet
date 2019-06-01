/*
 * Copyright (c) 2018 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 *
 * unpackInt, unpackLong originally come from MapDB http://www.mapdb.org/
 * licensed under the Apache License, Version 2.0
 */

package ninja.blacknet.serialization

import kotlinx.io.core.ByteReadPacket
import kotlinx.io.core.IoBuffer
import kotlinx.io.core.readBytes
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.ElementValueDecoder
import kotlinx.serialization.SerialDescriptor
import kotlinx.serialization.internal.EnumDescriptor
import java.nio.ByteBuffer
import kotlin.experimental.and

class BinaryDecoder(private val input: ByteReadPacket) : ElementValueDecoder() {
    fun <T : Any?> decode(loader: DeserializationStrategy<T>): T? {
        val v = loader.deserialize(this)
        if (input.remaining > 0) {
            input.release()
            return null
        }
        return v
    }

    override fun decodeByte(): Byte = input.readByte()
    override fun decodeInt(): Int = input.readInt()
    override fun decodeLong(): Long = input.readLong()

    override fun decodeString(): String {
        val size = unpackInt()
        return String(input.readBytes(size))
    }

    override fun decodeEnum(enumDescription: EnumDescriptor): Int = unpackInt()
    override fun decodeCollectionSize(desc: SerialDescriptor): Int = unpackInt()

    fun decodeSerializableByteArrayValue(): SerializableByteArray {
        val size = unpackInt()
        return SerializableByteArray(input.readBytes(size))
    }

    fun decodeByteArrayValue(size: Int): ByteArray {
        return input.readBytes(size)
    }

    fun unpackInt(): Int {
        var ret = 0
        var v: Byte
        do {
            v = input.readByte()
            ret = ret shl 7 or (v and 0x7F.toByte()).toInt()
        } while (v and 0x80.toByte() == 0.toByte())
        return ret
    }

    fun unpackLong(): Long {
        var ret = 0L
        var v: Byte
        do {
            v = input.readByte()
            ret = ret shl 7 or (v and 0x7F.toByte()).toLong()
        } while (v and 0x80.toByte() == 0.toByte())
        return ret
    }

    companion object {
        fun fromBytes(bytes: ByteArray): BinaryDecoder {
            val buf = IoBuffer(ByteBuffer.wrap(bytes))
            buf.resetForRead()
            val input = ByteReadPacket(buf, IoBuffer.NoPool)
            return BinaryDecoder(input)
        }
    }
}
