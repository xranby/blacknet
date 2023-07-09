/*
 * Copyright (c) 2018-2019 Pavel Vasin
 * Copyright (c) 2018 Blacknet Team
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.db

import com.google.common.collect.Maps.newHashMapWithExpectedSize
import com.google.common.collect.Sets.newHashSetWithExpectedSize
import io.ktor.util.error
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.Serializable
import kotlinx.serialization.internal.HashMapSerializer
import mu.KotlinLogging
import ninja.blacknet.Runtime
import ninja.blacknet.network.Address
import ninja.blacknet.network.AddressV1
import ninja.blacknet.network.Network
import ninja.blacknet.network.Node
import ninja.blacknet.serialization.BinaryDecoder
import ninja.blacknet.serialization.BinaryEncoder
import ninja.blacknet.serialization.Json
import ninja.blacknet.util.SynchronizedHashMap
import ninja.blacknet.util.delay
import kotlin.math.exp
import kotlin.math.max
import kotlin.math.min
import kotlin.math.pow
import kotlin.random.Random

private val logger = KotlinLogging.logger {}

object PeerDB {
    const val DELAY = 60 * 60
    const val MAX_SIZE = 10000
    private const val VERSION = 3
    private val peers = SynchronizedHashMap<Address, Entry>(MAX_SIZE)
    private val PEER_KEY = "peer".toByteArray()
    private val STATE_KEY = "db".toByteArray()
    private val VERSION_KEY = "version".toByteArray()

    private fun setVersion(batch: LevelDB.WriteBatch) {
        val version = BinaryEncoder()
        version.encodeVarInt(VERSION)
        batch.put(PEER_KEY, VERSION_KEY, version.toBytes())
    }

    init {
        val stateBytes = LevelDB.get(PEER_KEY, STATE_KEY)
        val versionBytes = LevelDB.get(PEER_KEY, VERSION_KEY)

        val version = if (versionBytes != null) {
            BinaryDecoder.fromBytes(versionBytes).decodeVarInt()
        } else {
            1
        }

        val hashMap = if (version == VERSION) {
            if (stateBytes != null) {
                BinaryDecoder.fromBytes(stateBytes).decode(HashMapSerializer(Address.serializer(), Entry.serializer()))
            } else {
                emptyMap<Address, Entry>()
            }
        } else if (version in 1..2) {
            val batch = LevelDB.createWriteBatch()

            val updatedHashMap = if (stateBytes != null) {
                logger.info("Upgrading PeerDB...")
                val result = newHashMapWithExpectedSize<Address, Entry>(MAX_SIZE)
                try {
                    if (version == 2) {
                        val stateV2 = BinaryDecoder.fromBytes(stateBytes).decode(HashMapSerializer(AddressV1.serializer(), EntryV2.serializer()))
                        stateV2.forEach { (addressV1, entryV2) ->
                            result.put(Address(addressV1), Entry(entryV2))
                        }
                    } else if (version == 1) {
                        val stateV1 = BinaryDecoder.fromBytes(stateBytes).decode(HashMapSerializer(AddressV1.serializer(), EntryV1.serializer()))
                        stateV1.forEach { (addressV1, entryV1) ->
                            result.put(Address(addressV1), Entry(entryV1))
                        }
                    }
                } catch (e: Throwable) {
                    logger.error(e)
                }
                result
            } else {
                emptyMap<Address, Entry>()
            }

            setVersion(batch)

            if (updatedHashMap.isEmpty())
                batch.write()
            else
                commitImpl(updatedHashMap, batch, false)

            updatedHashMap
        } else {
            throw RuntimeException("Unknown database version $version")
        }

        logger.info("Loaded ${hashMap.size} peer addresses")

        peers.map.putAll(hashMap)

        Runtime.addShutdownHook {
            commit(true)
        }
        Runtime.rotate(::oldEntriesRemover)
    }

    suspend fun size(): Int {
        return peers.size()
    }

    suspend fun isEmpty(): Boolean {
        return peers.isEmpty()
    }

    suspend fun isLow(): Boolean {
        return peers.size() < 100
    }

    suspend fun connected(address: Address, time: Long, userAgent: String, prober: Boolean) {
        if (address.isLocal()) return
        peers.mutex.withLock {
            val entry = peers.map.get(address)
            if (entry != null)
                entry.connected(time, userAgent, prober)
            else
                peers.map.put(address, Entry.newConnected(time, userAgent))
        }
    }

    suspend fun failed(address: Address, time: Long) {
        if (Node.isOffline()) return
        peers.mutex.withLock {
            peers.map.get(address)?.failed(time)
        }
    }

    suspend fun getAll(): ArrayList<Pair<Address, Entry>> {
        return peers.copyToArray()
    }

    suspend fun getSeed(): List<Address> {
        return peers.filterToKeyList { address, entry -> address.port == Node.DEFAULT_P2P_PORT && entry.isReliable() }
    }

    suspend fun getCandidates(n: Int, predicate: (Address, Entry) -> Boolean): List<Address> {
        val candidates = peers.mutex.withLock {
            val candidates = ArrayList<Pair<Address, Float>>(peers.map.size)
            val currTime = Runtime.time()
            peers.map.forEach { (address, entry) ->
                if (predicate(address, entry))
                    candidates.add(Pair(address, entry.chance(currTime)))
            }
            candidates
        }

        if (candidates.size <= n)
            return candidates.map { (address, _) -> address }
        else if (candidates.size == 0)
            return emptyList()

        val x = min(candidates.size, n)
        val result = newHashSetWithExpectedSize<Address>(x)
        do {
            val (address, chance) = candidates.random()
            if (chance > Random.nextFloat())
                result.add(address)
        } while (result.size < x)
        return result.toList()
    }

    suspend fun getRandom(n: Int): ArrayList<Address> {
        val candidates = peers.keys()
        candidates.shuffle()
        val x = min(candidates.size, n)
        val result = ArrayList<Address>(x)
        for (i in 0 until x)
            result.add(candidates[i])
        return result
    }

    suspend fun add(newPeers: List<Address>, from: Address, force: Boolean = false): Int = peers.mutex.withLock {
        var added = 0
        var i = 0
        val newPeersSize = newPeers.size
        val nToAdd = if (!force) {
            val freeSlots = max(MAX_SIZE - peers.map.size, 0)
            min(newPeersSize, freeSlots)
        } else {
            newPeersSize
        }
        while (i < newPeersSize && added < nToAdd) {
            if (addImpl(newPeers[i], from))
                added += 1
            i += 1
        }
        return added
    }

    private fun addImpl(peer: Address, from: Address): Boolean {
        if (peer.isLocal())
            return false
        if (peer.isPrivate())
            return false
        if (peer.network == Network.TORv2) // obsolete
            return false
        if (peers.map.containsKey(peer))
            return false
        peers.map.put(peer, Entry.new(from))
        return true
    }

    suspend fun contains(peer: Address): Boolean {
        return peers.containsKey(peer)
    }

    private suspend fun oldEntriesRemover() {
        delay(DELAY)

        if (Node.isOffline())
            return

        val toRemove = ArrayList<Address>()
        peers.mutex.withLock {
            val currTime = Runtime.time()
            peers.map.forEach { (address, entry) ->
                if (entry.isOld(currTime))
                    toRemove.add(address)
            }
            if (!toRemove.isEmpty()) {
                toRemove.forEach { peers.map.remove(it) }
                val batch = LevelDB.createWriteBatch()
                commitImpl(peers.map, batch, false)
                logger.info("Removed ${toRemove.size} old entries from peer db")
            }
        }
    }

    private suspend fun commit(sync: Boolean = false) = peers.mutex.withLock {
        val batch = LevelDB.createWriteBatch()
        commitImpl(peers.map, batch, sync)
    }

    private fun commitImpl(map: Map<Address, Entry>, batch: LevelDB.WriteBatch, sync: Boolean) {
        val bytes = BinaryEncoder.toBytes(HashMapSerializer(Address.serializer(), Entry.serializer()), map)
        batch.put(PEER_KEY, STATE_KEY, bytes)
        batch.write(sync)
    }

    @Serializable
    class NetworkStat(
            var lastConnected: Long,
            var userAgent: String,
            val stat2H: UptimeStat,
            val stat8H: UptimeStat,
            val stat1D: UptimeStat,
            val stat1W: UptimeStat,
            val stat1M: UptimeStat
    ) {
        internal constructor(lastConnected: Long, userAgent: String) : this(
                lastConnected,
                userAgent,
                UptimeStat(),
                UptimeStat(),
                UptimeStat(),
                UptimeStat(),
                UptimeStat()
        )
    }

    @Serializable
    class Entry(
            val from: Address,
            var attempts: Int,
            var lastTry: Long,
            var stat: NetworkStat?
    ) {
        internal constructor(entry: EntryV1) : this(Address(entry.from), entry.attempts, entry.lastTry, null)
        internal constructor(entry: EntryV2) : this(Address(entry.from), entry.attempts, entry.lastTry, entry.stat)

        fun toJson(address: Address) = Json.toJson(Info.serializer(), Info(this, address))

        fun failed(time: Long) {
            stat?.let { updateUptimeStat(it, false, time) }
            attempts += 1
            lastTry = time
        }

        @Suppress("UNUSED_PARAMETER")
        fun connected(time: Long, userAgent: String, prober: Boolean) {
            if (stat != null) {
                stat!!.lastConnected = time
                stat!!.userAgent = userAgent
            } else {
                stat = NetworkStat(time, userAgent)
            }
            updateUptimeStat(stat!!, true, time)
            attempts = 0
            lastTry = time
        }

        fun chance(time: Long): Float {
            val age = time - lastTry
            val chance = 0.66f.pow(min(attempts, 8))
            return if (age > 15 * 60)
                chance
            else
                chance * 0.01f
        }

        fun isNew(): Boolean {
            return stat == null && attempts == 0
        }

        fun isOld(currTime: Long): Boolean {
            val lastConnected = stat?.lastConnected ?: 0L

            if (lastConnected == 0L && attempts > 15)
                return true
            if (lastConnected != 0L && currTime - lastConnected > 15 * 24 * 60 * 60)
                return true

            return false
        }

        fun isReliable(): Boolean {
            val stat = stat ?: return false

            if (stat.stat2H.reliability > 0.85f && stat.stat2H.count > 2f) return true
            if (stat.stat8H.reliability > 0.70f && stat.stat8H.count > 4f) return true
            if (stat.stat1D.reliability > 0.55f && stat.stat1D.count > 8f) return true
            if (stat.stat1W.reliability > 0.45f && stat.stat1W.count > 16f) return true
            if (stat.stat1M.reliability > 0.35f && stat.stat1M.count > 32f) return true

            return false
        }

        private fun updateUptimeStat(stat: NetworkStat, good: Boolean, time: Long) {
            val age = time - lastTry
            stat.stat2H.update(good, age, 3600.0f * 2)
            stat.stat8H.update(good, age, 3600.0f * 8)
            stat.stat1D.update(good, age, 3600.0f * 24)
            stat.stat1W.update(good, age, 3600.0f * 24 * 7)
            stat.stat1M.update(good, age, 3600.0f * 24 * 30)
        }

        companion object {
            fun new(from: Address) = Entry(from, 0, 0, null)
            fun newConnected(time: Long, userAgent: String) = Entry(Network.LOOPBACK, 0, 0, NetworkStat(time, userAgent))
        }

        @Suppress("unused")
        @Serializable
        class Info(
                val address: String,
                val from: String,
                val attempts: Int,
                var lastTry: Long,
                val stat: NetworkStat?
        ) {
            constructor(entry: Entry, address: Address) : this(
                    address.toString(),
                    entry.from.toString(),
                    entry.attempts,
                    entry.lastTry,
                    entry.stat
            )
        }
    }

    @Serializable
    class UptimeStat(var weight: Float, var count: Float, var reliability: Float) {
        constructor() : this(0.0f, 0.0f, 0.0f)

        fun update(good: Boolean, age: Long, tau: Float) {
            val f: Float = exp(-age / tau)
            reliability = reliability * f + if (good) 1.0f - f else 0.0f
            count = count * f + 1.0f
            weight = weight * f + (1.0f - f)
        }
    }

    @Serializable
    internal class EntryV1(val from: AddressV1, val attempts: Int, val lastTry: Long, val lastConnected: Long)

    @Serializable
    internal class EntryV2(val from: AddressV1, val attempts: Int, val lastTry: Long, val stat: NetworkStat?)
}
