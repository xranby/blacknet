/*
 * Copyright (c) 2018 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.network

import io.ktor.network.sockets.ServerSocket
import io.ktor.network.sockets.aSocket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import mu.KotlinLogging
import ninja.blacknet.Config
import ninja.blacknet.Config.dnsseed
import ninja.blacknet.Config.incomingconnections
import ninja.blacknet.Config.listen
import ninja.blacknet.Config.mintxfee
import ninja.blacknet.Config.outgoingconnections
import ninja.blacknet.Config.port
import ninja.blacknet.Config.upnp
import ninja.blacknet.core.DataDB.Status
import ninja.blacknet.core.DataType
import ninja.blacknet.core.PoS
import ninja.blacknet.core.TxPool
import ninja.blacknet.crypto.BigInt
import ninja.blacknet.crypto.Hash
import ninja.blacknet.db.BlockDB
import ninja.blacknet.db.LedgerDB
import ninja.blacknet.db.PeerDB
import ninja.blacknet.util.SynchronizedArrayList
import ninja.blacknet.util.SynchronizedHashSet
import ninja.blacknet.util.delay
import java.math.BigDecimal
import java.net.InetSocketAddress
import java.time.Instant
import kotlin.coroutines.CoroutineContext
import kotlin.random.Random

private val logger = KotlinLogging.logger {}

object Node : CoroutineScope {
    const val DEFAULT_P2P_PORT = 28453
    const val NETWORK_TIMEOUT = 90
    const val magic = 0x17895E7D
    const val version = 9
    const val minVersion = 5
    override val coroutineContext: CoroutineContext = Dispatchers.Default
    private val shutdownHooks = SynchronizedArrayList<suspend () -> Unit>()
    val nonce = Random.nextLong()
    val connections = SynchronizedArrayList<Connection>()
    val listenAddress = SynchronizedHashSet<Address>()
    var minTxFee = parseAmount(Config[mintxfee])

    init {
        Runtime.getRuntime().addShutdownHook(Thread {
            runBlocking {
                shutdownHooks.reversedForEach {
                    it()
                }
            }
        })

        logger.info("${Runtime.getRuntime().availableProcessors()} CPU available")

        if (Config[listen]) {
            try {
                Node.listenOnIP()
                if (Config[upnp])
                    launch { UPnP.forward() }
            } catch (e: Throwable) {
            }
        }
        launch { listenOnTor() }
        launch { listenOnI2P() }
        launch { connector() }
        launch { pinger() }
        launch { peerAnnouncer() }
        launch { dnsSeeder(true) }
        launch { inventoryBroadcaster() }
    }

    /**
     * Registers a new shutdown hook.
     *
     * All registered shutdown hooks will be run sequentially in the reversed order.
     */
    fun addShutdownHook(hook: suspend () -> Unit) {
        runBlocking {
            shutdownHooks.add(hook)
        }
    }

    fun time(): Long {
        return Instant.now().getEpochSecond()
    }

    fun timeMilli(): Long {
        return Instant.now().toEpochMilli()
    }

    fun isTooFarInFuture(time: Long): Boolean {
        return time > Node.time() + 15
    }

    suspend fun outgoing(): Int {
        return connections.sumBy {
            when (it.state) {
                Connection.State.OUTGOING_CONNECTED -> 1
                else -> 0
            }
        }
    }

    suspend fun incoming(includeWaiting: Boolean = false): Int {
        return connections.sumBy {
            if (includeWaiting)
                when (it.state) {
                    Connection.State.INCOMING_CONNECTED -> 1
                    Connection.State.INCOMING_WAITING -> 1
                    else -> 0
                }
            else
                when (it.state) {
                    Connection.State.INCOMING_CONNECTED -> 1
                    else -> 0
                }
        }
    }

    suspend fun connected(): Int {
        return connections.sumBy {
            when (it.state) {
                Connection.State.OUTGOING_CONNECTED -> 1
                Connection.State.INCOMING_CONNECTED -> 1
                else -> 0
            }
        }
    }

    suspend fun isOffline(): Boolean {
        return connected() == 0
    }

    fun getMaxPacketSize(): Int {
        return LedgerDB.maxBlockSize() + 100
    }

    fun getMinPacketSize(): Int {
        return LedgerDB.DEFAULT_MAX_BLOCK_SIZE + 100
    }

    fun isInitialSynchronization(): Boolean {
        return ChainFetcher.isSynchronizing() && time() > LedgerDB.blockTime() + PoS.TARGET_BLOCK_TIME * PoS.MATURITY
    }

    fun listenOn(address: Address) {
        val addr = when (address.network) {
            Network.IPv4, Network.IPv6 -> address.getSocketAddress()
            else -> throw NotImplementedError("not implemented for " + address.network)
        }
        val server = aSocket(Network.selector).tcp().bind(addr)
        logger.info("Listening on $address")
        launch {
            listenAddress.add(address)
            listener(server)
        }
    }

    private fun listenOnIP() {
        if (Network.IPv4.isDisabled() && Network.IPv6.isDisabled())
            return
        if (Network.IPv4.isDisabled())
            return listenOn(Address.IPv6_ANY(Config[port]))
        listenOn(Address.IPv4_ANY(Config[port]))
    }

    private suspend fun listenOnTor() {
        val address = Network.listenOnTor()
        if (address != null) {
            if (!Config[listen] || Network.IPv4.isDisabled() && Network.IPv6.isDisabled())
                listenOn(Address.LOOPBACK)
            logger.info("Listening on $address")
            listenAddress.add(address)
        }
    }

    private suspend fun listenOnI2P() {
        val address = Network.listenOnI2P()
        if (address != null) {
            logger.info("Listening on $address")
            listenAddress.add(address)
            i2plistener()
        }
    }

    suspend fun connectTo(address: Address) {
        val connection = Network.connect(address)
        connections.add(connection)
        sendVersion(connection, nonce)
        connection.launch(this)
    }

    fun sendVersion(connection: Connection, nonce: Long) {
        val chain = if (isInitialSynchronization()) {
            ChainAnnounce.GENESIS
        } else {
            ChainAnnounce(LedgerDB.blockHash(), LedgerDB.cumulativeDifficulty())
        }
        val v = Version(magic, version, time(), nonce, Bip14.agent, minTxFee, chain)
        connection.sendPacket(v)
    }

    suspend fun announceChain(hash: Hash, cumulativeDifficulty: BigInt, source: Connection? = null) {
        val ann = ChainAnnounce(hash, cumulativeDifficulty)
        broadcastPacket(ann) {
            it != source && it.lastChain.chain != hash && it.version >= ChainAnnounce.MIN_VERSION
        }
        val inv = Pair(DataType.Block, hash)
        connections.forEach {
            if (it != source && it.state.isConnected() && it.version < ChainAnnounce.MIN_VERSION)
                it.inventory(inv)
        }
    }

    suspend fun broadcastBlock(hash: Hash, bytes: ByteArray): Boolean {
        val status = BlockDB.process(hash, bytes)
        if (status == Status.ACCEPTED) {
            announceChain(hash, LedgerDB.cumulativeDifficulty())
            return true
        } else {
            logger.info("$status block $hash")
            return false
        }
    }

    suspend fun broadcastTx(hash: Hash, bytes: ByteArray): Boolean {
        val status = TxPool.processTx(hash, bytes)
        if (status.first == Status.ACCEPTED) {
            val inv = Pair(DataType.Transaction, hash)
            connections.forEach {
                if (it.state.isConnected() && it.feeFilter <= status.second)
                    it.inventory(inv)
            }
            return true
        } else if (status.first == Status.ALREADY_HAVE) {
            logger.info("Already in tx pool $hash")
            return true
        } else {
            logger.info("${status.first} tx $hash")
            return false
        }
    }

    suspend fun broadcastInv(unfiltered: UnfilteredInvList, source: Connection? = null) {
        val invs = unfiltered.map { Pair(it.first, it.second) }
        val toSend = InvList(invs.size)
        connections.forEach {
            if (it != source && it.state.isConnected()) {
                for (i in unfiltered.indices) {
                    val inv = unfiltered[i]
                    if (inv.first != DataType.Transaction || it.feeFilter <= inv.third)
                        toSend.add(invs[i])
                }
                if (toSend.size != 0) {
                    it.inventory(toSend)
                    toSend.clear()
                }
            }
        }
    }

    private suspend fun broadcastPacket(packet: Packet, filter: (Connection) -> Boolean = { true }) {
        logger.debug { "Broadcasting ${packet.getType()}" }
        val bytes = packet.build()
        connections.forEach {
            if (it.state.isConnected() && filter(it))
                it.sendPacket(bytes.copy())
        }
        bytes.release()
    }

    private suspend fun listener(server: ServerSocket) {
        while (true) {
            val socket = server.accept()
            val remoteAddress = Network.address(socket.remoteAddress as InetSocketAddress)
            val localAddress = Network.address(socket.localAddress as InetSocketAddress)
            if (!localAddress.isLocal())
                listenAddress.add(localAddress)
            val connection = Connection(socket, socket.openReadChannel(), socket.openWriteChannel(true), remoteAddress, localAddress, Connection.State.INCOMING_WAITING)
            addConnection(connection)
        }
    }

    private suspend fun i2plistener() {
        while (I2PSAM.haveSession()) {
            val c = I2PSAM.accept() ?: continue
            val connection = Connection(c.socket, c.readChannel, c.writeChannel, c.remoteAddress, I2PSAM.localAddress!!, Connection.State.INCOMING_WAITING)
            addConnection(connection)
        }
    }

    private suspend fun addConnection(connection: Connection) {
        if (!haveSlot()) {
            logger.info("Too many connections, dropping ${connection.remoteAddress}")
            connection.close()
            return
        }
        connections.add(connection)
        connection.launch(this)
    }

    private suspend fun haveSlot(): Boolean {
        if (incoming(true) < Config[incomingconnections])
            return true
        return evictConnection()
    }

    private suspend fun evictConnection(): Boolean {
        val candidates = connections.copy().asSequence()
                .sortedBy { if (it.ping != 0L) it.ping else Long.MAX_VALUE }.drop(4)
                .sortedByDescending { it.lastTxTime }.drop(4)
                .sortedByDescending { it.lastBlockTime }.drop(4)
                .sortedBy { it.connectedAt }.drop(4)
                .toMutableList()

        //TODO network groups

        if (candidates.isEmpty())
            return false

        val connection = candidates.random()
        logger.info("Evicting ${connection.remoteAddress}")
        connection.close()
        return true
    }

    private suspend fun connector() {
        if (PeerDB.isEmpty()) {
            delay(DNS_TIMEOUT)
        }

        while (true) {
            val n = Config[outgoingconnections] - outgoing()
            if (n <= 0) {
                delay(NETWORK_TIMEOUT)
                continue
            }

            val filter = connections.map { it.remoteAddress }.plus(listenAddress.toList())

            val addresses = PeerDB.getCandidates(n, filter)
            if (addresses.isEmpty()) {
                logger.info("Don't have candidates in PeerDB. ${outgoing()} connections, max ${Config[outgoingconnections]}")
                delay(PeerDB.DELAY)
                dnsSeeder(false)
                continue
            }

            addresses.forEach { PeerDB.attempt(it) }

            addresses.forEach {
                val address = it
                Node.launch {
                    try {
                        connectTo(address)
                    } catch (e: Throwable) {
                    }
                }
            }

            delay(NETWORK_TIMEOUT)
        }
    }

    private suspend fun pinger() {
        while (true) {
            delay(NETWORK_TIMEOUT)

            val currTime = time()
            connections.forEach {
                if (it.state.isWaiting()) {
                    if (currTime > it.connectedAt + NETWORK_TIMEOUT)
                        it.close()
                } else {
                    if (it.pingRequest == null) {
                        if (it.ping != 0L && currTime > it.lastPacketTime + NETWORK_TIMEOUT) {
                            logger.debug { "Sending ping to ${it.remoteAddress}" }
                            sendPing(it)
                        } else if (it.ping == 0L) {
                            sendPing(it)
                        }
                    } else {
                        logger.info("Disconnecting ${it.remoteAddress} on ping timeout")
                        it.close()
                    }
                }
            }
        }
    }
    private fun sendPing(connection: Connection) {
        val id = Random.nextInt()
        connection.pingRequest = Connection.PingRequest(id, timeMilli())
        connection.sendPacket(Ping(id))
    }

    private suspend fun peerAnnouncer() {
        while (true) {
            delay(5 * 60 + Random.nextInt(5 * 60))

            val randomPeers = PeerDB.getRandom(Peers.MAX)
            if (randomPeers.size == 0)
                continue

            val myAddress = listenAddress.filterToList { !it.isLocal() && !it.isPrivate() && !PeerDB.contains(it) }
            if (myAddress.size != 0) {
                val i = Random.nextInt(randomPeers.size * 10)
                if (i < randomPeers.size) {
                    randomPeers[i] = myAddress[Random.nextInt(myAddress.size)]
                    logger.info("Announcing ${randomPeers[i]}")
                }
            }

            broadcastPacket(Peers(randomPeers))
        }
    }

    private const val DNS_TIMEOUT = 5
    private const val DNS_SEEDER_DELAY = 11
    private suspend fun dnsSeeder(delay: Boolean) {
        if (!Config[dnsseed])
            return

        if (delay && !PeerDB.isEmpty()) {
            delay(DNS_SEEDER_DELAY)
            if (connected() >= 2) {
                logger.info("P2P peers available. Skipped DNS seeding.")
                return
            }
        }

        logger.info("Requesting DNS seeds.")

        val seeds = "dnsseed.blacknet.ninja"
        try {
            val peers = Network.resolveAll(seeds, DEFAULT_P2P_PORT)
            PeerDB.add(peers, Address.LOOPBACK)
        } catch (e: Throwable) {
        }
    }

    private const val INV_TIMEOUT = 5
    private suspend fun inventoryBroadcaster() {
        while (true) {
            delay(INV_TIMEOUT)
            val currTime = time()
            connections.forEach {
                if (it.state.isConnected() && currTime >= it.lastInvSentTime + INV_TIMEOUT) {
                    it.sendInventory(currTime)
                }
            }
        }
    }

    private fun parseAmount(string: String): Long {
        val n = (BigDecimal(string) * BigDecimal(PoS.COIN)).longValueExact()
        if (n < 0) throw RuntimeException("Negative amount")
        return n
    }
}