/*
 * Copyright (c) 2019 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.api

import kotlinx.serialization.Serializable

@Serializable
class StakingInfo(
        val stakingAccounts: Int,
        val hashRate: Double,
        val weight: String,
        val networkWeight: String,
        val expectedTime: Long
)
