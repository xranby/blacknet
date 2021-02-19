/*
 * Copyright (c) 2018-2020 Pavel Vasin
 * Copyright (c) 2019 Blacknet Team
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.rpc.v2

import io.ktor.routing.Route
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import ninja.blacknet.core.Staker
import ninja.blacknet.crypto.PrivateKeySerializer
import ninja.blacknet.crypto.PublicKeySerializer
import ninja.blacknet.rpc.requests.*

fun Route.staking() {
    @Serializable
    class StartStaking(
            @SerialName("mnemonic")
            @Serializable(with = PrivateKeySerializer::class)
            val privateKey: ByteArray
    ) : Request {
        override suspend fun handle(): TextContent {
            return respondText(Staker.startStaking(privateKey).toString())
        }
    }

    post(StartStaking.serializer(), "/api/v2/startstaking")

    @Serializable
    class StopStaking(
            @SerialName("mnemonic")
            @Serializable(with = PrivateKeySerializer::class)
            val privateKey: ByteArray
    ) : Request {
        override suspend fun handle(): TextContent {
            return respondText(Staker.stopStaking(privateKey).toString())
        }
    }

    post(StopStaking.serializer(), "/api/v2/stopstaking")

    @Serializable
    class IsStaking(
            @SerialName("mnemonic")
            @Serializable(with = PrivateKeySerializer::class)
            val privateKey: ByteArray
    ) : Request {
        override suspend fun handle(): TextContent {
            return respondText(Staker.isStaking(privateKey).toString())
        }
    }

    post(IsStaking.serializer(), "/api/v2/isstaking")

    @Serializable
    class Staking(
            @SerialName("address")
            @Serializable(with = PublicKeySerializer::class)
            val publicKey: ByteArray? = null
    ) : Request {
        override suspend fun handle(): TextContent {
            return respondJson(StakingInfo.serializer(), Staker.info(publicKey))
        }
    }

    get(Staking.serializer(), "/api/v2/staking/{address?}")
}
