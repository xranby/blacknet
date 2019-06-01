/*
 * Copyright (c) 2019 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.db

import mu.KotlinLogging
import ninja.blacknet.Config
import ninja.blacknet.Config.dbcache
import org.iq80.leveldb.*
import java.io.File

private val logger = KotlinLogging.logger {}

object LevelDB {
    private val factory: DBFactory = loadFactory()
    private val db: DB = factory.open(File(Config.dataDir + "/leveldb"), options())

    internal fun iterator(): DBIterator {
        return db.iterator()
    }

    fun getProperty(name: String): String? {
        return db.getProperty(name)
    }

    internal fun key(key1: ByteArray, key2: ByteArray): ByteArray {
        return key1 + key2
    }

    internal fun get(key: ByteArray): ByteArray? {
        return db.get(key)
    }

    fun get(key1: ByteArray, key2: ByteArray): ByteArray? {
        return db.get(key(key1, key2))
    }

    fun contains(key1: ByteArray, key2: ByteArray): Boolean {
        return get(key1, key2) != null
    }

    fun put(key1: ByteArray, key2: ByteArray, bytes: ByteArray) {
        db.put(key(key1, key2), bytes)
    }

    fun delete(key1: ByteArray, key2: ByteArray) {
        db.delete(key(key1, key2))
    }

    fun createWriteBatch(): WriteBatch {
        return WriteBatch(db.createWriteBatch())
    }

    class WriteBatch internal constructor(private val batch: org.iq80.leveldb.WriteBatch) {
        internal fun put(key: ByteArray, bytes: ByteArray) {
            batch.put(key, bytes)
        }

        fun put(key1: ByteArray, key2: ByteArray, bytes: ByteArray) {
            batch.put(key(key1, key2), bytes)
        }

        internal fun delete(key: ByteArray) {
            batch.delete(key)
        }

        fun delete(key1: ByteArray, key2: ByteArray) {
            batch.delete(key(key1, key2))
        }

        fun write(sync: Boolean = false) {
            db.write(batch, if (sync) syncOptions else writeOptions)
            batch.close()
        }

        fun close() {
            batch.close()
        }
    }

    private fun options(): Options {
        val cacheSize = Config[dbcache] * 1048576
        val options = Options()
                .createIfMissing(true)
                .paranoidChecks(true)
                .compressionType(CompressionType.NONE)
                .cacheSize(cacheSize / 2L)
                .writeBufferSize(cacheSize / 4)
                .maxOpenFiles(64)
                .logger(DBLogger)
        logger.info("LevelDB cache ${Config[dbcache]} MiB, max open files ${options.maxOpenFiles()}")
        return options
    }

    private fun loadFactory(): DBFactory {
        for (impl in arrayOf(
                Pair("LevelDB JNI", "org.fusesource.leveldbjni.JniDBFactory"),
                Pair("LevelDB Java", "org.iq80.leveldb.impl.Iq80DBFactory"))) {
            for (loader in arrayOf(ClassLoader.getSystemClassLoader(), javaClass.classLoader)) {
                try {
                    val factory = loader.loadClass(impl.second).getConstructor().newInstance() as DBFactory
                    logger.info("Loaded ${impl.first}")
                    return factory
                } catch (e: Throwable) {
                }
            }
        }
        throw RuntimeException("Can't load LevelDB")
    }

    private object DBLogger : Logger {
        override fun log(message: String) = logger.debug { "LevelDB: $message" }
    }

    private val writeOptions = WriteOptions()
    private val syncOptions = WriteOptions().sync(true)
}
