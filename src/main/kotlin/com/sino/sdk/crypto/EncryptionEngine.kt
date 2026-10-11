package com.sino.sdk.crypto

import java.io.InputStream
import java.io.OutputStream

/**
 * AES-256-GCM over java.io streams, the same engine core uses on Android and desktop.
 */
interface EncryptionEngine {
    fun generateDEK(): ByteArray
    fun generateIV(): ByteArray
    fun encrypt(inputStream: InputStream, outputStream: OutputStream, key: ByteArray, iv: ByteArray)
    fun decrypt(inputStream: InputStream, outputStream: OutputStream, key: ByteArray, iv: ByteArray)

    // ELITE: Chunked GCM for Direct Cloud Streaming. Format v2 (big-endian chunk counter in IV bytes 8..11) is the only
    // format; it matches core's CryptoConstants.CHUNK_FORMAT_VERSION.
    fun encryptChunked(inputStream: InputStream, outputStream: OutputStream, key: ByteArray, iv: ByteArray, chunkSize: Int = 1024 * 1024, version: Int = 2)
    fun decryptChunked(inputStream: InputStream, outputStream: OutputStream, key: ByteArray, iv: ByteArray, chunkSize: Int = 1024 * 1024, version: Int = 2)

    // ELITE: Partial Decryption (Random Access)
    fun decryptRange(
        inputStream: InputStream,
        outputStream: OutputStream,
        key: ByteArray,
        iv: ByteArray,
        startByte: Long,
        length: Long,
        totalSize: Long,
        chunkSize: Int = 1024 * 1024,
        streamOffset: Long = 0,
        version: Int = 2
    )
}
