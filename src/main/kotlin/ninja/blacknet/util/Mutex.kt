/*
 * Copyright (c) 2019-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.util

import kotlinx.coroutines.sync.Mutex

suspend inline fun <T> Mutex.withUnlock(owner: Any? = null, action: () -> T): T {
    // Experimental contracts
    // import kotlin.contracts.*
    // contract {
    //     callsInPlace(action, InvocationKind.EXACTLY_ONCE)
    // }
    unlock(owner)
    try {
        return action()
    } finally {
        lock(owner)
    }
}
