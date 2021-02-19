/*
 * Copyright (c) 2019-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.rpc.v2

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import ninja.blacknet.serialization.json.json

@Serializable
class WebSocketNotification(
        val route: String,
        val message: JsonElement
) {
    constructor(notification: BlockNotification) : this(
            "block",
            json.encodeToJsonElement(BlockNotification.serializer(), notification)
    )

    constructor(notification: TransactionNotification) : this(
            "transaction",
            json.encodeToJsonElement(TransactionNotification.serializer(), notification)
    )
}
