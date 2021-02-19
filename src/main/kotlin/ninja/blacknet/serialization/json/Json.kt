/*
 * Copyright (c) 2019-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.serialization.json

import kotlinx.serialization.json.Json
import ninja.blacknet.serialization.textModule

/**
 * Instance of JSON serialization.
 */
public val json: Json = Json {
    prettyPrint = System.getProperty("ninja.blacknet.serialization.json.indented")?.toBoolean() ?: false
    prettyPrintIndent = "    "
    serializersModule = textModule
}
