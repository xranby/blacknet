/*
 * Copyright (c) 2019-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.rpc.v1

import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.SerializationStrategy
import kotlinx.serialization.json.JsonElement
import ninja.blacknet.serialization.json.json

/**
 * Instance of JSON serialization.
 */
@Deprecated("")
object Json {
    private val instance = json

    fun <T> stringify(serializer: SerializationStrategy<T>, value: T): String = instance.encodeToString(serializer, value)
    fun <T : Any?> toJson(serializer: SerializationStrategy<T>, value: T): JsonElement = instance.encodeToJsonElement(serializer, value)
    fun <T> parse(deserializer: DeserializationStrategy<T>, string: String): T = instance.decodeFromString(deserializer, string)
    fun parseJson(string: String): JsonElement = instance.parseToJsonElement(string)
    fun <T> fromJson(deserializer: DeserializationStrategy<T>, json: JsonElement): T = instance.decodeFromJsonElement(deserializer, json)
}
