/*
 * Copyright (c) 2018-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet

import kotlinx.serialization.Serializable
import ninja.blacknet.crypto.PoS
import ninja.blacknet.crypto.PrivateKeySerializer
import ninja.blacknet.serialization.config.ConfigFormat
import ninja.blacknet.serialization.textModule

@Serializable
class Config(
        val minfeerate: String,
        val ipv4: Boolean,
        val ipv6: Boolean,
        val listen: Boolean,
        val port: Int,
        val tor: Boolean,
        val i2p: Boolean,
        val upnp: Boolean,
        val incomingconnections: Int,
        val outgoingconnections: Int,
        val proxyhost: String? = null,
        val proxyport: Int? = null,
        val torhost: String? = null,
        val torport: Int? = null,
        val torcontrol: Int,
        val i2psamhost: String? = null,
        val i2psamport: Int? = null,
        val dbcache: Size,
        var mnemonics: List<@Serializable(PrivateKeySerializer::class) ByteArray>? = null,
        // val master: String,
        // val slave: String,
        val softblocksizelimit: Size = Size(PoS.MAX_BLOCK_SIZE),
        val txpoolsize: Size = Size(128 * 1024 * 1024),
        val logips: Boolean = false,
        // val whitelist: Set<String>? = null,
        // val blacklist: Set<String>? = null,
        val debugcoroutines: Boolean = false,
        val rpcserver: Boolean = true,
        val seqthreshold: Int = Int.MAX_VALUE - 1,
) {
    companion object {
        val instance = ConfigFormat(serializersModule = textModule).decodeFromFile(serializer(), "blacknet.conf").also {
            if (it.dbcache.bytes < 1024 * 1024) throw ConfigError("dbcache ${it.dbcache.hrp(false)} is unrealistically low")
            if (it.txpoolsize.bytes < 1024 * 1024) throw ConfigError("txpoolsize ${it.txpoolsize.hrp(false)} is unrealistically low")
        }
    }
}

private class ConfigError(message: String) : Error(message)
