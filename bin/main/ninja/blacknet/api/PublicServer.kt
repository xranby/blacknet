/*
 * Copyright (c) 2019 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.api

import io.ktor.application.Application
import io.ktor.application.call
import io.ktor.application.install
import io.ktor.features.DefaultHeaders
import io.ktor.response.respond
import io.ktor.routing.get
import io.ktor.routing.routing
import ninja.blacknet.serialization.Json

fun Application.PublicServer() {
    install(DefaultHeaders)

    routing {
        get("/api/v1/supply") {
            call.respond(Json.stringify(SupplyInfo.serializer(), SupplyInfo.get()))
        }
    }
}
