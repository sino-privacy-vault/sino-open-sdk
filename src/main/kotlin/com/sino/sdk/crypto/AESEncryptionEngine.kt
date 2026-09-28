package com.sino.sdk.crypto

import java.io.InputStream
import java.io.OutputStream
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Core engine for AES-256-GCM encryption and decryption.
 * Verifiable implementation of Sino's Zero-Knowledge encryption.
 * Hardened v2: Implements versioned nonce derivation and self-seeking logic.
 */
class AESEncryptionEngine : EncryptionEngine {

    companion object {
        private const val ALGORITHM = "AES/GCM/NoPadding"
        private const val TAG_LENGTH_BITS = 128
        private const val TAG_SIZE_BYTES = 16
        private const val IV_LENGTH_BYTES = 12
        private const val KEY_SIZE_BYTES = 32 // 256 bits
    }

    override fun encrypt(
        inputStream: InputStream,
        outputStream: OutputStream,
        key: ByteArray,
        iv: ByteArray
    ) {
        val cipher = Cipher.getInstance(ALGORITHM)
        val spec = GCMParameterSpec(TAG_LENGTH_BITS, iv)
        val secretKey = SecretKeySpec(key, "AES")
        
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec)

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

    override fun decrypt(
        inputStream: InputStream,
        outputStream: OutputStream,
        key: ByteArray,
        iv: ByteArray
    ) {
        val cipher = Cipher.getInstance(ALGORITHM)
        val spec = GCMParameterSpec(TAG_LENGTH_BITS, iv)
        val secretKey = SecretKeySpec(key, "AES")

        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)

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

    override fun encryptChunked(
        inputStream: InputStream,
        outputStream: OutputStream,
        key: ByteArray,
        iv: ByteArray,
        chunkSize: Int,
        version: Int
    ) {
        val secretKey = SecretKeySpec(key, "AES")
        val buffer = ByteArray(chunkSize)
        var chunkIndex = 0L

        try {
            while (true) {
                var totalRead = 0
                while (totalRead < chunkSize) {
                    val r = inputStream.read(buffer, totalRead, chunkSize - totalRead)
                    if (r == -1) break
                    totalRead += r
                }

                if (totalRead == 0) break

                val currentIv = incrementIV(iv, chunkIndex, version)
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
        val secretKey = SecretKeySpec(key, "AES")
        val encryptedChunkSize = chunkSize + TAG_SIZE_BYTES
        val buffer = ByteArray(encryptedChunkSize)
        var chunkIndex = 0L

        try {
            while (true) {
                var totalRead = 0
                while (totalRead < encryptedChunkSize) {
                    val r = inputStream.read(buffer, totalRead, encryptedChunkSize - totalRead)
                    if (r == -1) break
                    totalRead += r
                }

                if (totalRead == 0) break

                val currentIv = incrementIV(iv, chunkIndex, version)
                val cipher = Cipher.getInstance(ALGORITHM)
                cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(TAG_LENGTH_BITS, currentIv))
                
                val decrypted = cipher.doFinal(buffer, 0, totalRead)
                outputStream.write(decrypted)
                
                chunkIndex++
            }
        } finally {
            SecurityUtils.fillZero(buffer)
        }
    }

    override fun decryptRange(
        inputStream: InputStream,
        outputStream: OutputStream,
        key: ByteArray,
        iv: ByteArray,
        startByte: Long,
        length: Long,
        totalSize: Long,
        chunkSize: Int,
        version: Int,
        streamOffset: Long
    ) {
        val secretKey = SecretKeySpec(key, "AES")
        val encryptedChunkSize = chunkSize + TAG_SIZE_BYTES
        
        var currentPlaintextPos = startByte
        val endPlaintextPos = startByte + length
        var currentStreamPos = streamOffset
        
        while (currentPlaintextPos < endPlaintextPos) {
            val chunkIndex = currentPlaintextPos / chunkSize
            val requiredStreamPos = chunkIndex * encryptedChunkSize.toLong()

            // ELITE: Self-Seeking Logic (Hardened against zero-returning InputStream.skip)
            if (currentStreamPos < requiredStreamPos) {
                val toSkip = requiredStreamPos - currentStreamPos
                var skipped = 0L
                while (skipped < toSkip) {
                    val res = inputStream.skip(toSkip - skipped)
                    if (res <= 0) {
                        // FALLBACK: On non-blocking or chunked streams where skip returns <= 0, read into scratch buffer
                        val scratchSize = kotlin.math.min(4096L, toSkip - skipped).toInt()
                        val scratch = ByteArray(scratchSize)
                        val readBytes = inputStream.read(scratch, 0, scratchSize)
                        if (readBytes == -1) break // True EOF
                        skipped += readBytes
                    } else {
                        skipped += res
                    }
                }
                currentStreamPos += skipped
            }

            val currentIv = incrementIV(iv, chunkIndex, version)
            val cipher = Cipher.getInstance(ALGORITHM)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(TAG_LENGTH_BITS, currentIv))
            
            // ELITE: Hardened Full-Read for GCM packets
            val buffer = ByteArray(encryptedChunkSize)
            var totalRead = 0
            while (totalRead < encryptedChunkSize) {
                val r = inputStream.read(buffer, totalRead, encryptedChunkSize - totalRead)
                if (r == -1) break
                totalRead += r
            }
            currentStreamPos += totalRead

            if (totalRead < TAG_SIZE_BYTES) break
            
            val decrypted = cipher.doFinal(buffer, 0, totalRead)
            val offsetInChunk = (currentPlaintextPos % chunkSize).toInt()
            val bytesToTake = kotlin.math.min(decrypted.size - offsetInChunk, (endPlaintextPos - currentPlaintextPos).toInt())
            
            outputStream.write(decrypted, offsetInChunk, bytesToTake)
            
            currentPlaintextPos += bytesToTake
            SecurityUtils.fillZero(decrypted)
            SecurityUtils.fillZero(buffer)
        }
    }

    fun incrementIV(baseIv: ByteArray, counter: Long, version: Int): ByteArray {
        if (counter > 0xFFFFFFFFL) throw IllegalArgumentException("Nonce Overflow")
        
        val iv = baseIv.copyOf()
        if (version == 1) {
            val c = counter.toInt()
            iv[8] = (iv[8].toInt() xor (c ushr 24 and 0xFF)).toByte()
            iv[9] = (iv[9].toInt() xor (c ushr 16 and 0xFF)).toByte()
            iv[10] = (iv[10].toInt() xor (c ushr 8 and 0xFF)).toByte()
            iv[11] = (iv[11].toInt() xor (c and 0xFF)).toByte()
        } else {
            iv[8] = (counter ushr 24 and 0xFFL).toByte()
            iv[9] = (counter ushr 16 and 0xFFL).toByte()
            iv[10] = (counter ushr 8 and 0xFFL).toByte()
            iv[11] = (counter and 0xFFL).toByte()
        }
        return iv
    }

    override fun generateDEK(): ByteArray {
        val dek = ByteArray(KEY_SIZE_BYTES)
        SecureRandom().nextBytes(dek)
        return dek
    }

    override fun generateIV(): ByteArray {
        val iv = ByteArray(IV_LENGTH_BYTES)
        SecureRandom().nextBytes(iv)
        return iv
    }
}
