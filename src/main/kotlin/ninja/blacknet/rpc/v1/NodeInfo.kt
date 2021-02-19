/*
 * Copyright (c) 2018-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.rpc.v1

import kotlinx.serialization.Serializable
import ninja.blacknet.Version
import ninja.blacknet.db.BlockDB
import ninja.blacknet.db.LedgerDB
import ninja.blacknet.network.Node
import ninja.blacknet.network.UserAgent

@Serializable
class NodeInfo(
        val agent: String,
        val name: String,
        val version: String,
        val protocolVersion: Int,
        val outgoing: Int,
        val incoming: Int,
        val listening: List<String>,
        val warnings: List<String>
) {
    companion object {
        suspend fun get(): NodeInfo {
            val listening = Node.listenAddress.mapToList { it.toString() }
            val warnings = BlockDB.warnings() + LedgerDB.warnings() + Node.warnings()
            return NodeInfo(
                    UserAgent.string,
                    Version.name,
                    Version.version,
                    Node.version,
                    Node.outgoing(),
                    Node.incoming(),
                    listening,
                    warnings)
        }
    }
}
