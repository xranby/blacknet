/*
 * Copyright (c) 2018 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.api

import kotlinx.serialization.Serializable
import ninja.blacknet.db.PeerDB

@Serializable
class PeerDBInfo(
        val size: Int,
        val peers: List<String>
) {
    companion object {
        suspend fun get(): PeerDBInfo {
            val peers = PeerDB.getAll().map { it.toString() }
            return PeerDBInfo(peers.size, peers)
        }
    }
}
