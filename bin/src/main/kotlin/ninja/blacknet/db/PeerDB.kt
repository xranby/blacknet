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

import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.Serializable
import kotlinx.serialization.internal.HashMapSerializer
import mu.KotlinLogging
import ninja.blacknet.network.Address
import ninja.blacknet.network.Node
import ninja.blacknet.serialization.BinaryDecoder
import ninja.blacknet.serialization.BinaryEncoder
import ninja.blacknet.util.SynchronizedHashMap
import ninja.blacknet.util.delay
import kotlin.math.min
import kotlin.random.Random

private val logger = KotlinLogging.logger {}

object PeerDB {
    const val DELAY = 60 * 60
    private const val MAX_SIZE = 10000
    private val map = SynchronizedHashMap<Address, Entry>(MAX_SIZE)
    private val PEER_KEY = "peer".toByteArray()
    private val STATE_KEY = "db".toByteArray()

    init {
        runBlocking {
            val bytes = LevelDB.get(PEER_KEY, STATE_KEY)
            if (bytes != null) {
                val hashMap = BinaryDecoder.fromBytes(bytes).decode(HashMapSerializer(Address.serializer(), Entry.serializer()))
                if (hashMap != null)
                    map.putAll(hashMap)
                else
                    logger.error("Deserialization error")
            }
            logger.info("Loaded ${map.size()} peer addresses")
        }

        Node.addShutdownHook { commit(true) }
        Node.launch { oldEntriesRemover() }
    }

    suspend fun size(): Int {
        return map.size()
    }

    suspend fun isEmpty(): Boolean {
        return map.isEmpty()
    }

    suspend fun connected(address: Address) {
        if (address.isLocal()) return
        val entry = map.get(address)
        if (entry != null)
            map.put(address, Entry(entry.from, 0, 0, Node.time()))
        else
            map.put(address, Entry(Address.LOOPBACK, 0, 0, Node.time()))
    }

    suspend fun attempt(address: Address) {
        if (address.isLocal()) return
        val entry = map.get(address)
        if (entry != null)
            map.put(address, Entry(entry.from, entry.attempts + 1, Node.time(), entry.lastConnected))
        else
            map.put(address, Entry(Address.LOOPBACK, 0, Node.time(), 0))
    }

    suspend fun getAll(): List<Address> {
        return map.keys()
    }

    suspend fun getCandidate(filter: List<Address>): Address? {
        val candidates = map.filterToKeyList { address, _ ->  !filter.contains(address) }
        if (candidates.isEmpty())
            return null
        return candidates[Random.nextInt(candidates.size)]
    }

    suspend fun getCandidates(n: Int, filter: List<Address>): List<Address> {
        val candidates = map.filterToKeyList { address, _ ->  !filter.contains(address) }
        if (candidates.isEmpty())
            return emptyList()
        candidates.shuffle()
        val x = min(candidates.size, n)
        return candidates.take(x)
    }

    suspend fun getRandom(n: Int): MutableList<Address> {
        val candidates = map.keys()
        candidates.shuffle()
        val x = min(size(), n)
        return candidates.asSequence().take(x).toMutableList()
    }

    suspend fun add(peers: List<Address>, from: Address) {
        if (map.size() >= MAX_SIZE)
            return
        peers.forEach {
            add(it, from)
        }
    }

    private suspend fun add(peer: Address, from: Address): Boolean {
        if (peer.network.isDisabled())
            return false
        if (peer.isLocal())
            return false
        if (peer.isPrivate() && !from.isPrivate())
            return false
        if (!map.containsKey(peer)) {
            map.put(peer, Entry(from, 0, 0, 0))
            return true
        }
        return false
    }

    suspend fun contains(peer: Address): Boolean {
        return map.containsKey(peer)
    }

    private suspend fun oldEntriesRemover() {
        while (true) {
            delay(DELAY)
            if (Node.isOffline()) continue

            val toRemove = ArrayList<Address>()
            val currTime = Node.time()
            map.forEach {
                if (it.value.isOld(currTime))
                    toRemove.add(it.key)
            }
            if (!toRemove.isEmpty()) {
                toRemove.forEach { map.remove(it) }
                commit()
                logger.info("Removed ${toRemove.size} old entries from peer db")
            }
        }
    }

    private suspend fun commit(sync: Boolean = false) = map.mutex.withLock {
        val bytes = BinaryEncoder.toBytes(HashMapSerializer(Address.serializer(), Entry.serializer()), map.map)
        val writeBatch = LevelDB.createWriteBatch()
        writeBatch.put(PEER_KEY, STATE_KEY, bytes)
        writeBatch.write(sync)
    }

    @Serializable
    class Entry(val from: Address, val attempts: Int, val lastTry: Long, val lastConnected: Long) {
        fun isOld(currTime: Long): Boolean {
            if (lastConnected == 0L && attempts > 15)
                return true
            if (lastConnected != 0L && currTime - lastConnected > 15 * 24 * 60 * 60)
                return true
            return false
        }
    }
}
