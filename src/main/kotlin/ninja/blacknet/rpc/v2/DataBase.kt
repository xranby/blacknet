/*
 * Copyright (c) 2018-2020 Pavel Vasin
 * Copyright (c) 2019 Blacknet Team
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.rpc.v2

import io.ktor.routing.Route
import java.io.File
import kotlin.math.abs
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.Serializable
import ninja.blacknet.core.ChainIndex
import ninja.blacknet.crypto.HashSerializer
import ninja.blacknet.crypto.PoS
import ninja.blacknet.crypto.PublicKeySerializer
import ninja.blacknet.dataDir
import ninja.blacknet.db.BlockDB
import ninja.blacknet.db.LedgerDB
import ninja.blacknet.db.LevelDB
import ninja.blacknet.rpc.RPCServer
import ninja.blacknet.rpc.requests.*
import ninja.blacknet.rpc.v1.LedgerInfo
import ninja.blacknet.rpc.v1.PeerDBInfo
import ninja.blacknet.util.buffered
import ninja.blacknet.util.data

fun Route.dataBase() {
    @Serializable
    class PeerDB : Request {
        override suspend fun handle(): TextContent {
            return respondJson(PeerDBInfo.serializer(), PeerDBInfo.get())
        }
    }

    get(PeerDB.serializer(), "/api/v2/peerdb")

    @Serializable
    class NetworkStat : Request {
        override suspend fun handle(): TextContent {
            return respondJson(PeerDBInfo.serializer(), PeerDBInfo.get(true))
        }
    }

    get(NetworkStat.serializer(), "/api/v2/peerdb/networkstat")

    @Serializable
    class LevelDBStats : Request {
        override suspend fun handle(): TextContent {
            return respondText(LevelDB.getProperty("leveldb.stats") ?: "Not implemented")
        }
    }

    get(LevelDBStats.serializer(), "/api/v2/leveldb/stats")

    @Serializable
    class Block(
            @Serializable(with = HashSerializer::class)
            val hash: ByteArray,
            val txdetail: Boolean = false
    ) : Request {
        override suspend fun handle(): TextContent {
            val (block, size) = BlockDB.block(hash) ?: return respondError("Block not found")
            return respondJson(BlockInfo.serializer(), BlockInfo(block, hash, size, txdetail))
        }
    }

    get(Block.serializer(), "/api/v2/block")
    get(Block.serializer(), "/api/v2/block/{hash}/{txdetail?}")

    @Serializable
    class BlockHash(
            val height: Int
    ) : Request {
        override suspend fun handle(): TextContent = BlockDB.mutex.withLock {
            val state = LedgerDB.state()
            if (height < 0 || height > state.height)
                return respondError("Block not found")
            else if (height == 0)
                return respondText(HashSerializer.encode(HashSerializer.ZERO))
            else if (height == state.height)
                return respondText(HashSerializer.encode(state.blockHash))

            val lastIndex = RPCServer.lastIndex
            if (lastIndex != null && lastIndex.second.height == height)
                return respondText(HashSerializer.encode(lastIndex.first))

            var hash: ByteArray
            var index: ChainIndex
            if (height < state.height / 2) {
                hash = HashSerializer.ZERO
                index = LedgerDB.getChainIndex(hash)!!
            } else {
                hash = state.blockHash
                index = LedgerDB.getChainIndex(hash)!!
            }
            if (lastIndex != null && abs(height - index.height) > abs(height - lastIndex.second.height))
                index = lastIndex.second
            while (index.height > height) {
                hash = index.previous
                index = LedgerDB.getChainIndex(hash)!!
            }
            while (index.height < height) {
                hash = index.next
                index = LedgerDB.getChainIndex(hash)!!
            }
            if (index.height < state.height - PoS.MATURITY + 1)
                RPCServer.lastIndex = Pair(hash, index)

            return respondText(HashSerializer.encode(hash))
        }
    }

    get(BlockHash.serializer(), "/api/v2/blockhash")
    get(BlockHash.serializer(), "/api/v2/blockhash/{height}")

    @Serializable
    class BlockIndex(
            @Serializable(with = HashSerializer::class)
            val hash: ByteArray
    ) : Request {
        override suspend fun handle(): TextContent {
            val index = LedgerDB.getChainIndex(hash)
            return if (index != null)
                respondJson(ChainIndex.serializer(), index)
            else
                respondError("Block not found")
        }
    }

    get(BlockIndex.serializer(), "/api/v2/blockindex")
    get(BlockIndex.serializer(), "/api/v2/blockindex/{hash}/")

    @Serializable
    class MakeBootstrap : Request {
        override suspend fun handle(): TextContent {
            val checkpoint = LedgerDB.state().rollingCheckpoint
            if (checkpoint.contentEquals(HashSerializer.ZERO))
                return respondError("Not synchronized")

            val file = File(dataDir, "bootstrap.dat.new")
            val stream = file.outputStream().buffered().data()

            var hash = HashSerializer.ZERO
            var index = LedgerDB.getChainIndex(hash)!!
            do {
                hash = index.next
                index = LedgerDB.getChainIndex(hash)!!
                val bytes = BlockDB.getImpl(hash)!!
                stream.writeInt(bytes.size)
                stream.write(bytes, 0, bytes.size)
            } while (!hash.contentEquals(checkpoint))

            stream.close()

            return respondText(file.absolutePath)
        }
    }

    get(MakeBootstrap.serializer(), "/api/v2/makebootstrap")

    @Serializable
    class Ledger : Request {
        override suspend fun handle(): TextContent {
            return respondJson(LedgerInfo.serializer(), LedgerInfo.get())
        }
    }

    get(Ledger.serializer(), "/api/v2/ledger")

    @Serializable
    class Account(
            @Serializable(with = PublicKeySerializer::class)
            val address: ByteArray,
            val confirmations: Int = PoS.DEFAULT_CONFIRMATIONS
    ) : Request {
        override suspend fun handle(): TextContent {
            val info = AccountInfo.get(address, confirmations)
            return if (info != null)
                respondJson(AccountInfo.serializer(), info)
            else
                respondError("Account not found")
        }
    }

    get(Account.serializer(), "/api/v2/account")
    get(Account.serializer(), "/api/v2/account/{address}/{confirmations?}")

    @Serializable
    class Check : Request {
        override suspend fun handle(): TextContent {
            return respondJson(LedgerDB.Check.serializer(), LedgerDB.check())
        }
    }

    get(Check.serializer(), "/api/v2/ledger/check")

    @Serializable
    class ScheduleSnapshot(
            val height: Int
    ) : Request {
        override suspend fun handle(): TextContent = BlockDB.mutex.withLock {
            val scheduled = LedgerDB.scheduleSnapshotImpl(height)
            return respondText(scheduled.toString())
        }
    }

    get(ScheduleSnapshot.serializer(), "/api/v2/ledger/schedulesnapshot")
    get(ScheduleSnapshot.serializer(), "/api/v2/ledger/schedulesnapshot/{height}")

    @Serializable
    class Snapshot(
            val height: Int
    ) : Request {
        override suspend fun handle(): TextContent {
            val snapshot = LedgerDB.getSnapshot(height)
            return if (snapshot != null)
                respondJson(LedgerDB.Snapshot.serializer(), snapshot)
            else
                respondError("Snapshot not found")
        }
    }

    get(Snapshot.serializer(), "/api/v2/ledger/snapshot")
    get(Snapshot.serializer(), "/api/v2/ledger/snapshot/{height}")
}
