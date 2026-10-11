package com.sino.sdk.crypto

import java.io.EOFException
import java.io.InputStream
import java.io.OutputStream
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.math.min

/**
 * AES-256-GCM encryption and decryption, identical to the engine Sino uses on Android and desktop. Chunk format v2
 * only: each chunk's nonce is the base IV with bytes 8..11 replaced by the big-endian chunk index.
 */
class AESEncryptionEngine : EncryptionEngine {

    private val secureRandom = SecureRandom()

    companion object {
        private const val ALGORITHM = "AES/GCM/NoPadding"
        private const val TAG_LENGTH_BITS = 128
        private const val IV_LENGTH_BYTES = 12
        private const val KEY_SIZE_BYTES = 32 // 256 bits
        private const val CHUNK_FORMAT_VERSION = 2
    }

    private fun aesKey(key: ByteArray): SecretKeySpec {
        // AES-128/192 keys would be accepted silently by the JCE: only the 256-bit keys Sino generates are valid.
        require(key.size == KEY_SIZE_BYTES) { "AES key must be $KEY_SIZE_BYTES bytes" }
        return SecretKeySpec(key, "AES")
    }

    private fun requireIv(iv: ByteArray) {
        require(iv.size == IV_LENGTH_BYTES) { "AES-GCM IV must be $IV_LENGTH_BYTES bytes" }
    }

    private fun requireChunkParams(chunkSize: Int, version: Int) {
        // A non-positive chunk size used to make encryptChunked write nothing at all.
        require(chunkSize > 0) { "Chunk size must be positive" }
        require(version == CHUNK_FORMAT_VERSION) { "Unsupported chunk format version $version" }
    }

    /**
     * Encrypts an InputStream and writes to an OutputStream using the provided key and IV.
     */
    override fun encrypt(
        inputStream: InputStream,
        outputStream: OutputStream,
        key: ByteArray,
        iv: ByteArray,
    ) {
        requireIv(iv)
        val cipher = Cipher.getInstance(ALGORITHM)
        cipher.init(Cipher.ENCRYPT_MODE, aesKey(key), GCMParameterSpec(TAG_LENGTH_BITS, iv))

        val buffer = ByteArray(8192)
        try {
            var bytesRead = inputStream.read(buffer)
            while (bytesRead != -1) {
                val encrypted = cipher.update(buffer, 0, bytesRead)
                if (encrypted != null) outputStream.write(encrypted)
                bytesRead = inputStream.read(buffer)
            }
            val finalBlock = cipher.doFinal()
            if (finalBlock != null) outputStream.write(finalBlock)
        } finally {
            SecurityUtils.fillZero(buffer)
        }
    }

    /**
     * Decrypts an InputStream and writes to an OutputStream using the provided key and IV.
     */
    override fun decrypt(
        inputStream: InputStream,
        outputStream: OutputStream,
        key: ByteArray,
        iv: ByteArray,
    ) {
        requireIv(iv)
        val cipher = Cipher.getInstance(ALGORITHM)
        cipher.init(Cipher.DECRYPT_MODE, aesKey(key), GCMParameterSpec(TAG_LENGTH_BITS, iv))

        val buffer = ByteArray(8192)
        try {
            var bytesRead = inputStream.read(buffer)
            while (bytesRead != -1) {
                val decrypted = cipher.update(buffer, 0, bytesRead)
                if (decrypted != null) outputStream.write(decrypted)
                bytesRead = inputStream.read(buffer)
            }
            val finalBlock = cipher.doFinal()
            if (finalBlock != null) outputStream.write(finalBlock)
        } finally {
            SecurityUtils.fillZero(buffer)
        }
    }

    /** One-shot AES-256-GCM (`ciphertext || tag`), used for wrapped keys and artifacts. */
    fun encrypt(data: ByteArray, key: ByteArray, iv: ByteArray): ByteArray {
        requireIv(iv)
        return Cipher.getInstance(ALGORITHM).run {
            init(Cipher.ENCRYPT_MODE, aesKey(key), GCMParameterSpec(TAG_LENGTH_BITS, iv))
            doFinal(data)
        }
    }

    /** One-shot AES-256-GCM decryption of `ciphertext || tag`; throws if the tag does not verify. */
    fun decrypt(data: ByteArray, key: ByteArray, iv: ByteArray): ByteArray {
        requireIv(iv)
        return Cipher.getInstance(ALGORITHM).run {
            init(Cipher.DECRYPT_MODE, aesKey(key), GCMParameterSpec(TAG_LENGTH_BITS, iv))
            doFinal(data)
        }
    }

    /**
     * ELITE: Chunked GCM Encryption.
     * Divides the file into fixed-size authenticated packets. Each chunk's nonce is the base IV with bytes 8..11
     * overwritten by the big-endian chunk index (format v2, the only format).
     */
    override fun encryptChunked(
        inputStream: InputStream,
        outputStream: OutputStream,
        key: ByteArray,
        iv: ByteArray,
        chunkSize: Int,
        version: Int
    ) {
        requireChunkParams(chunkSize, version)
        requireIv(iv)
        val secretKey = aesKey(key)
        val buffer = ByteArray(chunkSize)
        var chunkIndex = 0L

        try {
            while (true) {
                // ELITE: Technical "Full Read" loop to ensure consistent chunk sizes.
                // Prevents fragmentation between Android and Windows seeking logic.
                var totalRead = 0
                while (totalRead < chunkSize) {
                    val r = inputStream.read(buffer, totalRead, chunkSize - totalRead)
                    if (r == -1) break
                    totalRead += r
                }

                if (totalRead == 0) break

                val currentIv = chunkIv(iv, chunkIndex)
                val cipher = Cipher.getInstance(ALGORITHM)
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(TAG_LENGTH_BITS, currentIv))

                val encrypted = cipher.doFinal(buffer, 0, totalRead)
                outputStream.write(encrypted)

                chunkIndex++
            }
        } finally {
            SecurityUtils.fillZero(buffer)
        }
    }

    override fun decryptChunked(
        inputStream: InputStream,
        outputStream: OutputStream,
        key: ByteArray,
        iv: ByteArray,
        chunkSize: Int,
        version: Int
    ) {
        requireChunkParams(chunkSize, version)
        requireIv(iv)
        val secretKey = aesKey(key)
        val encryptedChunkSize = chunkSize + (TAG_LENGTH_BITS / 8)
        val buffer = ByteArray(encryptedChunkSize)
        var chunkIndex = 0L

        try {
            while (true) {
                // ELITE: Ensure we read exactly one authenticated packet (Plain + Tag).
                var totalRead = 0
                while (totalRead < encryptedChunkSize) {
                    val r = inputStream.read(buffer, totalRead, encryptedChunkSize - totalRead)
                    if (r == -1) break
                    totalRead += r
                }

                if (totalRead == 0) break

                val currentIv = chunkIv(iv, chunkIndex)
                val cipher = Cipher.getInstance(ALGORITHM)
                cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(TAG_LENGTH_BITS, currentIv))

                val decrypted = cipher.doFinal(buffer, 0, totalRead)
                outputStream.write(decrypted)
                SecurityUtils.fillZero(decrypted)

                chunkIndex++
            }
        } finally {
            SecurityUtils.fillZero(buffer)
        }
    }

    /**
     * ELITE: Partial Decryption (Random Access).
     * Decrypts plaintext bytes [startByte, startByte + length) (clamped to [totalSize]) from a stream positioned at
     * [streamOffset] of the ciphertext, skipping forward to the first chunk needed.
     * Fails with [EOFException] when the ciphertext ends before the range is complete: a short read used to return
     * a silently truncated range.
     */
    override fun decryptRange(
        inputStream: InputStream,
        outputStream: OutputStream,
        key: ByteArray,
        iv: ByteArray,
        startByte: Long,
        length: Long,
        totalSize: Long,
        chunkSize: Int,
        streamOffset: Long,
        version: Int
    ) {
        requireChunkParams(chunkSize, version)
        requireIv(iv)
        require(startByte >= 0 && length >= 0 && streamOffset >= 0) { "Invalid range" }
        val secretKey = aesKey(key)
        val tagSize = TAG_LENGTH_BITS / 8
        val encryptedChunkSize = chunkSize + tagSize

        var currentPlaintextPos = startByte
        val endPlaintextPos = if (totalSize >= 0) min(startByte + length, totalSize) else startByte + length
        var currentStreamPos = streamOffset
        val buffer = ByteArray(encryptedChunkSize)

        try {
            while (currentPlaintextPos < endPlaintextPos) {
                val chunkIndex = currentPlaintextPos / chunkSize
                val requiredStreamPos = chunkIndex * encryptedChunkSize.toLong()
                // A stream already past the chunk cannot be rewound (it would decrypt the wrong bytes).
                require(currentStreamPos <= requiredStreamPos) { "The stream starts after the requested range" }

                // ELITE: Self-Seeking Logic (Hardened against zero-returning InputStream.skip)
                if (currentStreamPos < requiredStreamPos) {
                    skipFully(inputStream, requiredStreamPos - currentStreamPos)
                    currentStreamPos = requiredStreamPos
                }

                // ELITE: Hardened Full-Read for GCM packets
                var totalRead = 0
                while (totalRead < encryptedChunkSize) {
                    val r = inputStream.read(buffer, totalRead, encryptedChunkSize - totalRead)
                    if (r == -1) break
                    totalRead += r
                }
                currentStreamPos += totalRead

                val offsetInChunk = (currentPlaintextPos % chunkSize).toInt()
                if (totalRead - tagSize <= offsetInChunk) throw EOFException("The encrypted stream ended before the requested range")

                val cipher = Cipher.getInstance(ALGORITHM)
                cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(TAG_LENGTH_BITS, chunkIv(iv, chunkIndex)))
                val decrypted = cipher.doFinal(buffer, 0, totalRead)
                try {
                    // Handle partial chunk reads (if startByte is not chunk-aligned)
                    val bytesToTake = min((decrypted.size - offsetInChunk).toLong(), endPlaintextPos - currentPlaintextPos).toInt()
                    outputStream.write(decrypted, offsetInChunk, bytesToTake)
                    currentPlaintextPos += bytesToTake
                } finally {
                    SecurityUtils.fillZero(decrypted)
                }
            }
        } finally {
            SecurityUtils.fillZero(buffer)
        }
    }

    /** Skips exactly [count] bytes, reading through streams whose skip() returns 0; fails at end of stream. */
    private fun skipFully(inputStream: InputStream, count: Long) {
        var skipped = 0L
        var scratch: ByteArray? = null
        while (skipped < count) {
            val res = inputStream.skip(count - skipped)
            if (res > 0) {
                skipped += res
                continue
            }
            // FALLBACK: On non-blocking or chunked streams where skip returns <= 0, read into a scratch buffer
            val buf = scratch ?: ByteArray(4096).also { scratch = it }
            val readBytes = inputStream.read(buf, 0, min(buf.size.toLong(), count - skipped).toInt())
            if (readBytes == -1) throw EOFException("The encrypted stream ended before the requested range")
            skipped += readBytes
        }
    }

    /**
     * The nonce of chunk [counter]: the base IV with bytes 8..11 overwritten by the big-endian chunk index.
     * GCM 96-bit nonce safety limit: 2^32 chunks per key.
     */
    private fun chunkIv(baseIv: ByteArray, counter: Long): ByteArray {
        if (counter > 0xFFFFFFFFL) {
            throw IllegalArgumentException("GCM Nonce Overflow: Too many chunks for a single IV/Key pair.")
        }
        val iv = baseIv.copyOf()
        iv[8] = (counter ushr 24 and 0xFFL).toByte()
        iv[9] = (counter ushr 16 and 0xFFL).toByte()
        iv[10] = (counter ushr 8 and 0xFFL).toByte()
        iv[11] = (counter and 0xFFL).toByte()
        return iv
    }

    /**
     * Generates a random 256-bit Data Encryption Key (DEK).
     */
    override fun generateDEK(): ByteArray {
        val dek = ByteArray(KEY_SIZE_BYTES)
        secureRandom.nextBytes(dek)
        return dek
    }

    /**
     * Generates a random 96-bit Initialization Vector (IV).
     */
    override fun generateIV(): ByteArray {
        val iv = ByteArray(IV_LENGTH_BYTES)
        secureRandom.nextBytes(iv)
        require(iv.size == IV_LENGTH_BYTES) { "AES-GCM IV must be exactly 12 bytes (96 bits)" }
        require(iv.any { it != 0.toByte() }) { "Generated IV cannot be all zeros" }
        return iv
    }
}
