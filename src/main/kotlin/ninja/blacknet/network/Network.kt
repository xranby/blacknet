/*
 * Copyright (c) 2018-2019 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.network

import com.google.common.net.InetAddresses
import io.ktor.network.selector.ActorSelectorManager
import io.ktor.network.sockets.aSocket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.util.error
import kotlinx.coroutines.Dispatchers
import mu.KotlinLogging
import ninja.blacknet.Config
import ninja.blacknet.Config.proxyhost
import ninja.blacknet.Config.proxyport
import ninja.blacknet.Config.torhost
import ninja.blacknet.Config.torport
import ninja.blacknet.crypto.Base32
import ninja.blacknet.util.byteArrayOfInts
import ninja.blacknet.util.delay
import ninja.blacknet.util.startsWith
import java.net.ConnectException
import java.net.InetAddress
import java.net.InetSocketAddress
import kotlin.experimental.and
import kotlin.math.min

private val logger = KotlinLogging.logger {}

enum class Network(val type: Byte, val addrSize: Int) {
    IPv4(128, 4),
    IPv6(129, 16),
    TORv2(130, 10),
    TORv3(131, 32),
    I2P(132, 32),
    ;

    constructor(type: Int, addrSize: Int) : this(type.toByte(), addrSize)

    fun isDisabled(): Boolean {
        return Config.isDisabled(this)
    }

    companion object {
        const val TOR_SUFFIX = ".onion"
        const val I2P_SUFFIX = ".b32.i2p"
        val IPv4_LOOPBACK_BYTES = byteArrayOf(127, 0, 0, 1)
        val IPv6_ANY_BYTES = ByteArray(Network.IPv6.addrSize)
        val IPv6_LOOPBACK_BYTES = byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)
        val LOOPBACK = Address.IPv4_LOOPBACK(Config.netPort)

        private val socksProxy: Address?
        private val torProxy: Address?

        init {
            if (Config.contains(proxyhost) && Config.contains(proxyport))
                socksProxy = Network.resolve(Config[proxyhost], Config[proxyport].toPort())
            else
                socksProxy = null

            if (Config.contains(torhost) && Config.contains(torport))
                torProxy = Network.resolve(Config[torhost], Config[torport].toPort())
            else
                torProxy = null
        }

        fun get(type: Byte): Network {
            return when (type) {
                IPv4.type -> IPv4
                IPv6.type -> IPv6
                TORv2.type -> TORv2
                TORv3.type -> TORv3
                I2P.type -> I2P
                else -> throw RuntimeException("Unknown network type $type")
            }
        }

        fun address(inet: InetSocketAddress): Address {
            return address(inet.getAddress(), inet.port.toPort())
        }

        fun address(inet: InetAddress, port: Short): Address {
            val bytes = inet.getAddress()
            return when (bytes.size) {
                IPv6.addrSize -> Address(IPv6, port, bytes)
                IPv4.addrSize -> Address(IPv4, port, bytes)
                else -> throw RuntimeException("Unknown IP address length ${bytes.size}")
            }
        }

        suspend fun connect(address: Address, prober: Boolean): Connection {
            if (address.network.isDisabled()) throw RuntimeException("${address.network} is disabled")
            val state = if (prober) Connection.State.PROBER_WAITING else Connection.State.OUTGOING_WAITING
            when (address.network) {
                IPv4, IPv6 -> {
                    if (socksProxy != null) {
                        val c = Socks5.connect(socksProxy, address)
                        return Connection(c.socket, c.readChannel, c.writeChannel, address, socksProxy, state)
                    } else {
                        val socket = aSocket(selector).tcp().connect(address.getSocketAddress())
                        val localAddress = Network.address(socket.localAddress as InetSocketAddress)
                        if (Config.netListen && !localAddress.isLocal())
                            Node.listenAddress.add(Address(localAddress.network, Config.netPort, localAddress.bytes))
                        return Connection(socket, socket.openReadChannel(), socket.openWriteChannel(true), address, localAddress, state)
                    }
                }
                TORv3 -> {
                    if (torProxy == null) throw RuntimeException("Tor proxy is not set")
                    val c = Socks5.connect(torProxy, address)
                    return Connection(c.socket, c.readChannel, c.writeChannel, address, torProxy, state)
                }
                I2P -> {
                    val c = I2PSAM.connect(address)
                    return Connection(c.socket, c.readChannel, c.writeChannel, address, I2PSAM.session().second, state)
                }
                TORv2 -> {
                    throw RuntimeException("${address.network} is obsolete")
                }
            }
        }

        suspend fun listenOnTor() {
            if (!Config.netListen || Network.IPv4.isDisabled() && Network.IPv6.isDisabled())
                Node.listenOn(Network.LOOPBACK)

            var timeout = 60

            while (true) {
                try {
                    val (coroutine, localAddress) = TorController.listen()

                    logger.info("Listening on ${localAddress.debugName()}")
                    Node.listenAddress.add(localAddress)

                    coroutine.join()

                    Node.listenAddress.remove(localAddress)
                    logger.info("Lost connection to tor controller")

                    timeout = 60
                } catch (e: ConnectException) {
                    logger.debug { "Can't connect to tor controller: ${e.message}" }
                } catch (e: Throwable) {
                    logger.info(e.message)
                }

                delay(timeout)
                timeout = min(timeout * 2, 3840)
            }
        }

        suspend fun listenOnI2P() {
            var timeout = 60

            while (true) {
                try {
                    val (_, localAddress) = I2PSAM.createSession()

                    logger.info("Listening on ${localAddress.debugName()}")
                    Node.listenAddress.add(localAddress)

                    while (true) {
                        val a = try {
                            I2PSAM.accept()
                        } catch (e: Throwable) {
                            break
                        }
                        val connection = Connection(a.socket, a.readChannel, a.writeChannel, a.remoteAddress, localAddress, Connection.State.INCOMING_WAITING)
                        Node.addConnection(connection)
                    }

                    Node.listenAddress.remove(localAddress)
                    logger.info("I2P SAM session closed")

                    timeout = 60
                } catch (e: I2PSAM.NotConfigured) {
                    logger.info(e.message)
                    return
                } catch (e: I2PSAM.I2PException) {
                    logger.info(e.message)
                } catch (e: ConnectException) {
                    logger.debug { "Can't connect to I2P SAM: ${e.message}" }
                } catch (e: Throwable) {
                    logger.error(e)
                }

                delay(timeout)
                timeout = min(timeout * 2, 3840)
            }
        }

        fun parse(string: String?, port: Short): Address? {
            if (string == null) return null
            val host = string.toLowerCase()

            if (host.endsWith(TOR_SUFFIX)) {
                if (host.length == 16 + TOR_SUFFIX.length) {
                    val decoded = Base32.decode(host.substring(0, 16))
                    if (decoded != null && decoded.size == TORv2.addrSize) {
                        return Address(TORv2, port, decoded)
                    }
                } else if (host.length == 56 + TOR_SUFFIX.length) {
                    val decoded = Base32.decode(host.substring(0, 56))
                    if (decoded != null && decoded.size == 35 && decoded[34] == TorController.V3) {
                        val bytes = decoded.copyOf(32)
                        val checksum = TorController.checksum(bytes, TorController.V3)
                        if (checksum[0] == decoded[32] && checksum[1] == decoded[33]) {
                            return Address(TORv3, port, bytes)
                        }
                    }
                }
                return null
            }

            if (host.endsWith(I2P_SUFFIX)) {
                if (host.length == 52 + I2P_SUFFIX.length) {
                    val decoded = Base32.decode(host.substring(0, 52))
                    if (decoded != null && decoded.size == I2P.addrSize) {
                        return Address(I2P, port, decoded)
                    }
                }
                return null
            }

            var parsed: InetAddress? = null
            try {
                parsed = InetAddresses.forString(host)
            } catch (e: Throwable) {
            }
            if (parsed != null)
                return address(parsed, port)
            return null
        }

        fun parsePort(string: String): Short? {
            return try {
                string.toInt().toPort()
            } catch (e: Throwable) {
                null
            }
        }

        fun resolve(string: String, port: Short): Address? {
            return resolveAll(string, port).firstOrNull()
        }

        fun resolveAll(string: String, port: Short): List<Address> {
            val parsed = parse(string, port)
            if (parsed != null)
                return listOf(parsed)

            try {
                return InetAddress.getAllByName(string).map { Network.address(it, port) }
            } catch (e: Throwable) {
                return emptyList()
            }
        }

        val selector = ActorSelectorManager(Dispatchers.IO)
    }
}

fun Int.toPort(): Short {
    require(this in 0..65535) { "Port must be in range 0..65535" }
    return toUShort().toShort()
}

fun Short.toPort(): Int {
    return toUShort().toInt()
}
