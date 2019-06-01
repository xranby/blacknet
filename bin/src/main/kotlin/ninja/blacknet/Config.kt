/*
 * Copyright (c) 2018 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet

import com.natpryce.konfig.*
import ninja.blacknet.network.Network
import java.io.File

object Config {
    private val config = ConfigurationProperties.fromFile(File("config/blacknet.conf"))

    val mintxfee by stringType
    val dnsseed by booleanType
    val ipv4 by booleanType
    val ipv6 by booleanType
    val listen by booleanType
    val port by intType
    val tor by booleanType
    val i2p by booleanType
    val upnp by booleanType
    val incomingconnections by intType
    val outgoingconnections by intType
    val proxyhost by stringType
    val proxyport by intType
    val torhost by stringType
    val torport by intType
    val torcontrol by intType
    val i2psamhost by stringType
    val i2psamport by intType
    val dbcache by intType
    val mnemonics by listType(stringType)

    object apiserver : PropertyGroup() {
        val jsonindented by booleanType
    }

    operator fun <T> get(key: Key<T>): T = config[key]
    fun <T> contains(key: Key<T>): Boolean = config.contains(key)

    fun isDisabled(network: Network): Boolean = when (network) {
        Network.IPv4 -> !config[ipv4]
        Network.IPv6 -> !config[ipv6]
        Network.TORv2 -> !config[tor]
        Network.TORv3 -> !config[tor]
        Network.I2P -> !config[i2p]
    }

    fun jsonindented(): Boolean {
        if (contains(apiserver.jsonindented))
            return get(apiserver.jsonindented)
        return false
    }
}
