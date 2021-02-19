/*
 * Copyright (c) 2018-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.network

import kotlinx.coroutines.launch
import mu.KotlinLogging
import ninja.blacknet.Config
import ninja.blacknet.Runtime
import ninja.blacknet.Version
import org.bitlet.weupnp.GatewayDevice
import org.bitlet.weupnp.GatewayDiscover

private val logger = KotlinLogging.logger {}

object UPnP {
    private const val PROTOCOL = "TCP"

    fun forward() {
        logger.info("Looking for UPnP Gateway")
        val discover = GatewayDiscover()
        discover.discover()

        val gateway = discover.getValidGateway()
        if (gateway == null) {
            logger.info("No valid UPnP Gateway found")
            return
        }

        logger.info("Sending port mapping request")
        if (!gateway.addPortMapping(Config.instance.port.toPort().toPort(), Config.instance.port.toPort().toPort(), gateway.localAddress.hostAddress, PROTOCOL, Version.name)) {
            logger.info("Port mapping failed")
            return
        }

        var address: Address? = null
        try {
            address = Network.parse(gateway.externalIPAddress, Config.instance.port.toPort())
        } catch (e: Throwable) {
        }
        if (address != null) {
            Runtime.launch { Node.listenAddress.add(address) }
            logger.info("Mapped to $address")
        } else {
            logger.info("Mapped to unknown external address")
        }

        Runtime.addShutdownHook {
            remove(gateway)
        }
    }

    private fun remove(gateway: GatewayDevice) {
        logger.info("Removing port mapping")
        gateway.deletePortMapping(Config.instance.port.toPort().toPort(), PROTOCOL)
    }
}
