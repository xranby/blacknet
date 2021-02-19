/*
 * Copyright (c) 2018-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.network.packet

import kotlinx.serialization.KSerializer

enum class PacketType {
    Version,
    Ping,
    Pong,
    GetPeers,
    PeersV1,
    InventoryV1,
    GetData,
    Data,
    GetBlocks,
    Blocks,
    ChainAnnounce,
    ChainFork,
    Inventory,
    GetTransactions,
    Transactions,
    Peers,
    ;

    companion object {
        fun getSerializer(type: Int): KSerializer<out Packet> {
            return when (type) {
                Version.ordinal -> ninja.blacknet.network.packet.Version.serializer()
                Ping.ordinal -> ninja.blacknet.network.packet.Ping.serializer()
                Pong.ordinal -> ninja.blacknet.network.packet.Pong.serializer()
                GetPeers.ordinal -> throw RuntimeException("Obsolete packet type GetPeers")
                PeersV1.ordinal -> throw RuntimeException("Obsolete packet type PeersV1")
                InventoryV1.ordinal -> throw RuntimeException("Obsolete packet type InventoryV1")
                GetData.ordinal -> throw RuntimeException("Obsolete packet type GetData")
                Data.ordinal -> throw RuntimeException("Obsolete packet type Data")
                GetBlocks.ordinal -> ninja.blacknet.network.packet.GetBlocks.serializer()
                Blocks.ordinal -> ninja.blacknet.network.packet.Blocks.serializer()
                ChainAnnounce.ordinal -> ninja.blacknet.network.packet.ChainAnnounce.serializer()
                ChainFork.ordinal -> ninja.blacknet.network.packet.ChainFork.serializer()
                Inventory.ordinal -> ninja.blacknet.network.packet.Inventory.serializer()
                GetTransactions.ordinal -> ninja.blacknet.network.packet.GetTransactions.serializer()
                Transactions.ordinal -> ninja.blacknet.network.packet.Transactions.serializer()
                Peers.ordinal -> ninja.blacknet.network.packet.Peers.serializer()
                else -> throw RuntimeException("Unknown packet type $type")
            }
        }
    }
}
