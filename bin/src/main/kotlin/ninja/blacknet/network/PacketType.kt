/*
 * Copyright (c) 2018 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.network

import kotlinx.serialization.KSerializer

enum class PacketType {
    Version,
    Ping,
    Pong,
    GetPeers,
    Peers,
    Inventory,
    GetData,
    Data,
    GetBlocks,
    Blocks,
    ChainAnnounce,
    ;

    companion object {
        fun getSerializer(type: Int): KSerializer<out Packet>? {
            return when (type) {
                Version.ordinal -> ninja.blacknet.network.Version.serializer()
                Ping.ordinal -> ninja.blacknet.network.Ping.serializer()
                Pong.ordinal -> ninja.blacknet.network.Pong.serializer()
                GetPeers.ordinal -> ninja.blacknet.network.GetPeers.serializer()
                Peers.ordinal -> ninja.blacknet.network.Peers.serializer()
                Inventory.ordinal -> ninja.blacknet.network.Inventory.serializer()
                GetData.ordinal -> ninja.blacknet.network.GetData.serializer()
                Data.ordinal -> ninja.blacknet.network.Data.serializer()
                GetBlocks.ordinal -> ninja.blacknet.network.GetBlocks.serializer()
                Blocks.ordinal -> ninja.blacknet.network.Blocks.serializer()
                ChainAnnounce.ordinal -> ninja.blacknet.network.ChainAnnounce.serializer()
                else -> null
            }
        }
    }
}