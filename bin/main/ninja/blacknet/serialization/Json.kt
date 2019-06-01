/*
 * Copyright (c) 2019 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.serialization

import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.SerializationStrategy
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonConfiguration
import kotlinx.serialization.json.JsonElement
import ninja.blacknet.Config

object Json {
    private val json = Json(JsonConfiguration(prettyPrint = Config.jsonindented(), indent = "    "))

    fun <T> parse(deserializer: DeserializationStrategy<T>, string: String): T = json.parse(deserializer, string)
    fun <T> stringify(serializer: SerializationStrategy<T>, obj: T): String = json.stringify(serializer, obj)
    fun <T : Any?> toJson(serializer: SerializationStrategy<T>, obj: T): JsonElement = json.toJson(serializer, obj)
}
