package com.sino.sdk.crypto

import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class AESEncryptionEngineTest {

    private val engine = AESEncryptionEngine()

    @Test
    fun `test basic encryption and decryption`() {
        val originalText = "Sino Zero-Trust Security Verification"
        val password = "StrongMasterPassword123".toCharArray()
        val salt = engine.generateIV() // Using IV generator for random salt
        
        // Use KEK derivation
        val derivation = SinoKeyDerivation()
        val key = derivation.deriveKey(password, salt)
        val iv = engine.generateIV()

        // 1. Encrypt
        val inputStream = ByteArrayInputStream(originalText.toByteArray())
        val encryptedOutputStream = ByteArrayOutputStream()
        engine.encrypt(inputStream, encryptedOutputStream, key, iv)
        
        val encryptedData = encryptedOutputStream.toByteArray()
        assertTrue(encryptedData.isNotEmpty())
        assertTrue(encryptedData.toString(Charsets.UTF_8) != originalText)

        // 2. Decrypt
        val encryptedInputStream = ByteArrayInputStream(encryptedData)
        val decryptedOutputStream = ByteArrayOutputStream()
        engine.decrypt(encryptedInputStream, decryptedOutputStream, key, iv)
        
        val decryptedText = decryptedOutputStream.toString(Charsets.UTF_8)
        assertEquals(originalText, decryptedText)
    }

    @Test
    fun `test chunked encryption for streaming`() {
        // Create 2.5MB of data to test multiple 1MB chunks
        val size = (2.5 * 1024 * 1024).toInt()
        val originalData = ByteArray(size) { it.toByte() }
        val key = engine.generateDEK()
        val iv = engine.generateIV()

        // 1. Encrypt Chunked
        val inputStream = ByteArrayInputStream(originalData)
        val encryptedOutputStream = ByteArrayOutputStream()
        engine.encryptChunked(inputStream, encryptedOutputStream, key, iv, chunkSize = 1024 * 1024)
        
        val encryptedData = encryptedOutputStream.toByteArray()
        
        // 2. Decrypt Chunked
        val encryptedInputStream = ByteArrayInputStream(encryptedData)
        val decryptedOutputStream = ByteArrayOutputStream()
        engine.decryptChunked(encryptedInputStream, decryptedOutputStream, key, iv, chunkSize = 1024 * 1024)
        
        val decryptedData = decryptedOutputStream.toByteArray()
        assertTrue(originalData.contentEquals(decryptedData))
    }

    @Test
    fun `test decryptRange with self seeking logic`() {
        val chunkSize = 100
        val originalData = ByteArray(500) { (it % 256).toByte() }
        val key = engine.generateDEK()
        val iv = engine.generateIV()

        // 1. Encrypt Chunked (Small chunks for test)
        val inputStream = ByteArrayInputStream(originalData)
        val encryptedOutputStream = ByteArrayOutputStream()
        engine.encryptChunked(inputStream, encryptedOutputStream, key, iv, chunkSize = chunkSize)
        
        val encryptedData = encryptedOutputStream.toByteArray()

        // 2. Decrypt a range (Chunk 3: bytes 350-400)
        // Pass the ENTIRE encrypted stream (offset 0), engine must seek internally
        val startByte = 350L
        val length = 50L
        
        val encryptedInputStream = ByteArrayInputStream(encryptedData)
        val decryptedOutputStream = ByteArrayOutputStream()
        
        engine.decryptRange(
            inputStream = encryptedInputStream,
            outputStream = decryptedOutputStream,
            key = key,
            iv = iv,
            startByte = startByte,
            length = length,
            totalSize = originalData.size.toLong(),
            chunkSize = chunkSize,
            streamOffset = 0L // ELITE: Testing self-seeking logic
        )

        val decryptedData = decryptedOutputStream.toByteArray()
        val expectedSlice = originalData.sliceArray(350 until 400)
        
        assertTrue(expectedSlice.contentEquals(decryptedData), "Self-seeking decryptRange failed to align stream and restore data.")
    }

    @Test
    fun `test chunked encryption and decryption robustness against short reads`() {
        // Create 2MB of data (2 full 1MB chunks)
        val chunkSize = 1024 * 1024
        val size = 2 * chunkSize
        val originalData = ByteArray(size) { (it % 251).toByte() }
        val key = engine.generateDEK()
        val iv = engine.generateIV()

        // 1. Encrypt Chunked using a stream that only returns 64KB at a time
        val shortReadIn = ShortReadInputStream(originalData, 64 * 1024)
        val encryptedOutputStream = ByteArrayOutputStream()
        engine.encryptChunked(shortReadIn, encryptedOutputStream, key, iv, chunkSize = chunkSize)
        
        val encryptedData = encryptedOutputStream.toByteArray()
        
        // 2MB -> exactly 2 chunks of 1MB + 16 bytes each
        val expectedSize = 2 * (chunkSize + 16)
        assertEquals(expectedSize, encryptedData.size, "Short reads caused incorrect chunk fragmentation during encryption.")

        // 2. Decrypt Chunked using a stream that only returns 32KB at a time
        val shortReadEncIn = ShortReadInputStream(encryptedData, 32 * 1024)
        val decryptedOutputStream = ByteArrayOutputStream()
        engine.decryptChunked(shortReadEncIn, decryptedOutputStream, key, iv, chunkSize = chunkSize)
        
        val decryptedData = decryptedOutputStream.toByteArray()
        assertTrue(originalData.contentEquals(decryptedData), "Decrypted data corrupted after jittery short-read IO cycles.")
    }

    /**
     * ELITE TEST HELPER: Simulates a jittery stream that doesn't fill the buffer in one call.
     */
    private class ShortReadInputStream(val data: ByteArray, val maxRead: Int) : java.io.InputStream() {
        private var position = 0
        override fun read(): Int = if (position < data.size) data[position++].toInt() and 0xFF else -1
        
        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (position >= data.size) return -1
            val toRead = kotlin.math.min(len, kotlin.math.min(maxRead, data.size - position))
            System.arraycopy(data, position, b, off, toRead)
            position += toRead
            return toRead
        }
    }

    @Test
    fun `test decryptRange robustness when skip returns zero on non-blocking stream`() {
        val chunkSize = 100
        val originalData = ByteArray(500) { (it % 256).toByte() }
        val key = engine.generateDEK()
        val iv = engine.generateIV()

        val inputStream = ByteArrayInputStream(originalData)
        val encryptedOutputStream = ByteArrayOutputStream()
        engine.encryptChunked(inputStream, encryptedOutputStream, key, iv, chunkSize = chunkSize)
        
        val encryptedData = encryptedOutputStream.toByteArray()

        val zeroSkipIn = ZeroSkipInputStream(encryptedData)
        val decryptedOutputStream = ByteArrayOutputStream()
        
        engine.decryptRange(
            inputStream = zeroSkipIn,
            outputStream = decryptedOutputStream,
            key = key,
            iv = iv,
            startByte = 350L,
            length = 50L,
            totalSize = originalData.size.toLong(),
            chunkSize = chunkSize,
            streamOffset = 0L
        )

        val decryptedData = decryptedOutputStream.toByteArray()
        val expectedSlice = originalData.sliceArray(350 until 400)
        assertTrue(expectedSlice.contentEquals(decryptedData), "decryptRange failed to fall back to scratch buffer when skip() returned 0.")
    }

    private class ZeroSkipInputStream(val data: ByteArray) : java.io.InputStream() {
        private var position = 0
        override fun read(): Int = if (position < data.size) data[position++].toInt() and 0xFF else -1
        override fun skip(n: Long): Long = 0L
        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (position >= data.size) return -1
            val toRead = kotlin.math.min(len, data.size - position)
            System.arraycopy(data, position, b, off, toRead)
            position += toRead
            return toRead
        }
    }
}
