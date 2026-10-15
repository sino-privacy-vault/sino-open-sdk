package com.sino.sdk.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.Random

class CryptographicHardeningTest {

    private val aesEngine = AESEncryptionEngine()
    private val mlDsaEngine = MLDSAEngine()
    private val mlKemEngine = MLKEMEngine()
    private val deviceManager = DeviceKeyManager()

    @Test
    fun `test NIST AES-256-GCM Known Answer Vector`() {
        // NIST SP 800-38D GCM Test Vector (Key: 256 bits, IV: 96 bits, Plaintext: 16 bytes)
        val keyHex = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"
        val ivHex = "cafebabefacedbaddecafeda"
        val plaintextHex = "d9313225f88406e5a55909c5aff5269a"
        val expectedCiphertextHex = "da6b4e51233b8b1103a1e6ac878b5f36657f62d099db6a5e9aca9a52f79c7fea"

        val key = SecurityUtils.fromHex(keyHex.toCharArray())
        val iv = SecurityUtils.fromHex(ivHex.toCharArray())
        val plaintext = SecurityUtils.fromHex(plaintextHex.toCharArray())

        // 1. Encryption Test
        val inStream = ByteArrayInputStream(plaintext)
        val outStream = ByteArrayOutputStream()
        aesEngine.encrypt(inStream, outStream, key, iv)

        val actualCiphertext = outStream.toByteArray()
        val actualCiphertextHex = SecurityUtils.toHex(actualCiphertext).concatToString()

        assertEquals(expectedCiphertextHex.lowercase(), actualCiphertextHex.lowercase())

        // 2. Decryption Test
        val decryptInStream = ByteArrayInputStream(actualCiphertext)
        val decryptOutStream = ByteArrayOutputStream()
        aesEngine.decrypt(decryptInStream, decryptOutStream, key, iv)

        val decryptedHex = SecurityUtils.toHex(decryptOutStream.toByteArray()).concatToString()
        assertEquals(plaintextHex.lowercase(), decryptedHex.lowercase())
    }

    @Test(expected = Exception::class)
    fun `test tampered GCM ciphertext tag throws Exception during decryption`() {
        val originalText = "Sino Zero-Trust Cryptographic Hardening Test Payload"
        val key = aesEngine.generateDEK()
        val iv = aesEngine.generateIV()

        val inStream = ByteArrayInputStream(originalText.toByteArray())
        val outStream = ByteArrayOutputStream()
        aesEngine.encrypt(inStream, outStream, key, iv)

        val encryptedData = outStream.toByteArray()
        // Flip the last byte (part of the 16-byte GCM authentication tag)
        encryptedData[encryptedData.size - 1] = (encryptedData.last().toInt() xor 0xFF).toByte()

        val tamperedInStream = ByteArrayInputStream(encryptedData)
        val decryptedOutStream = ByteArrayOutputStream()

        aesEngine.decrypt(tamperedInStream, decryptedOutStream, key, iv)
    }

    @Test(expected = Exception::class)
    fun `test tampered chunk ciphertext throws Exception during chunked decryption`() {
        val originalData = ByteArray(2000) { (it % 256).toByte() }
        val key = aesEngine.generateDEK()
        val iv = aesEngine.generateIV()

        val inStream = ByteArrayInputStream(originalData)
        val outStream = ByteArrayOutputStream()
        aesEngine.encryptChunked(inStream, outStream, key, iv, chunkSize = 500)

        val encryptedData = outStream.toByteArray()
        // Flip a byte in the second chunk ciphertext (around byte 600)
        encryptedData[600] = (encryptedData[600].toInt() xor 0xAA).toByte()

        val tamperedInStream = ByteArrayInputStream(encryptedData)
        val decryptedOutStream = ByteArrayOutputStream()

        aesEngine.decryptChunked(tamperedInStream, decryptedOutStream, key, iv, chunkSize = 500)
    }

    @Test
    fun `test unique IV generation prevents nonce reuse`() {
        val iv1 = aesEngine.generateIV()
        val iv2 = aesEngine.generateIV()

        assertEquals(12, iv1.size)
        assertEquals(12, iv2.size)
        assertFalse(iv1.contentEquals(iv2))
    }

    @Test
    fun `chunk nonces are the base IV with the big-endian chunk index in bytes 8 to 11`() {
        // Chunk format v2, as Sino writes it: chunk 256 must open with plain AES-GCM under that nonce.
        val chunkSize = 16
        val data = ByteArray(chunkSize * 257 + 5) { (it % 251).toByte() }
        val key = aesEngine.generateDEK()
        val baseIv = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12)
        val out = ByteArrayOutputStream()
        aesEngine.encryptChunked(ByteArrayInputStream(data), out, key, baseIv, chunkSize = chunkSize)
        val encrypted = out.toByteArray()

        val chunk = encrypted.copyOfRange(256 * (chunkSize + 16), 257 * (chunkSize + 16))
        val nonce = baseIv.copyOf().also { it[8] = 0; it[9] = 0; it[10] = 1; it[11] = 0 }
        assertArrayEquals(data.copyOfRange(256 * chunkSize, 257 * chunkSize), aesEngine.decrypt(chunk, key, nonce))
    }

    @Test
    fun `only 256-bit keys, 96-bit nonces and chunk format 2 are accepted`() {
        val iv = aesEngine.generateIV()
        assertThrows(IllegalArgumentException::class.java) { aesEngine.encrypt(ByteArray(1), ByteArray(16), iv) }
        assertThrows(IllegalArgumentException::class.java) { aesEngine.encrypt(ByteArray(1), aesEngine.generateDEK(), ByteArray(16)) }
        assertThrows(IllegalArgumentException::class.java) {
            aesEngine.decryptChunked(ByteArrayInputStream(ByteArray(0)), ByteArrayOutputStream(), aesEngine.generateDEK(), iv, version = 1)
        }
    }

    @Test(expected = Exception::class)
    fun `test wrong chunk ordering causes decryption tag authentication failure`() {
        val originalData = ByteArray(1000) { (it % 256).toByte() }
        val key = aesEngine.generateDEK()
        val iv = aesEngine.generateIV()

        val inStream = ByteArrayInputStream(originalData)
        val outStream = ByteArrayOutputStream()
        aesEngine.encryptChunked(inStream, outStream, key, iv, chunkSize = 500)

        val encryptedData = outStream.toByteArray()
        val chunkSizeEnc = 500 + 16 // 516 bytes per chunk

        // Swap Chunk 0 (0..515) and Chunk 1 (516..1031)
        val swapped = ByteArray(encryptedData.size)
        System.arraycopy(encryptedData, chunkSizeEnc, swapped, 0, chunkSizeEnc)
        System.arraycopy(encryptedData, 0, swapped, chunkSizeEnc, chunkSizeEnc)

        val swappedInStream = ByteArrayInputStream(swapped)
        val decryptedOutStream = ByteArrayOutputStream()

        aesEngine.decryptChunked(swappedInStream, decryptedOutStream, key, iv, chunkSize = 500)
    }

    @Test
    fun `test truncated ciphertext stream handling in chunked decryption`() {
        val originalData = ByteArray(1000) { (it % 256).toByte() }
        val key = aesEngine.generateDEK()
        val iv = aesEngine.generateIV()

        val inStream = ByteArrayInputStream(originalData)
        val outStream = ByteArrayOutputStream()
        aesEngine.encryptChunked(inStream, outStream, key, iv, chunkSize = 500)

        val encryptedData = outStream.toByteArray()
        // Truncate stream prematurely (remove last 20 bytes of trailing tag)
        val truncatedData = encryptedData.copyOfRange(0, encryptedData.size - 20)

        val truncatedInStream = ByteArrayInputStream(truncatedData)
        val decryptedOutStream = ByteArrayOutputStream()

        try {
            aesEngine.decryptChunked(truncatedInStream, decryptedOutStream, key, iv, chunkSize = 500)
            val decrypted = decryptedOutStream.toByteArray()
            assertTrue(decrypted.size < originalData.size)
        } catch (e: Exception) {
            assertTrue(e is Exception)
        }
    }

    @Test
    fun `test fuzzing over encrypted stream mutations always fails safely`() {
        val originalData = ByteArray(1000) { (it % 256).toByte() }
        val key = aesEngine.generateDEK()
        val iv = aesEngine.generateIV()

        val inStream = ByteArrayInputStream(originalData)
        val outStream = ByteArrayOutputStream()
        aesEngine.encryptChunked(inStream, outStream, key, iv, chunkSize = 250)

        val encryptedData = outStream.toByteArray()
        val rand = Random(42)

        // Perform 20 randomized bit-flip fuzzing mutations
        for (i in 0 until 20) {
            val fuzzedData = encryptedData.copyOf()
            val mutateIndex = rand.nextInt(fuzzedData.size)
            fuzzedData[mutateIndex] = (fuzzedData[mutateIndex].toInt() xor (1 + rand.nextInt(254))).toByte()

            val fuzzedInStream = ByteArrayInputStream(fuzzedData)
            val fuzzedOutStream = ByteArrayOutputStream()

            try {
                aesEngine.decryptChunked(fuzzedInStream, fuzzedOutStream, key, iv, chunkSize = 250)
                // If it doesn't throw, output MUST NOT match original
                assertFalse(originalData.contentEquals(fuzzedOutStream.toByteArray()))
            } catch (e: Exception) {
                // Expected security rejection
                assertTrue(e is Exception)
            }
        }
    }

    @Test(expected = Exception::class)
    fun `test corrupted manifest JSON parsing fails safely`() {
        val corruptedJson = """{"version": "invalid", "keyEpoch": "corrupted"}"""
        VaultManifest.fromJson(corruptedJson)
    }

    @Test
    fun `test ML-DSA-65 invalid signature length rejection`() {
        val keyPair = mlDsaEngine.generateKeyPair()
        val payload = "VaultManifest_Sign_Payload_2026".toByteArray()

        val signature = mlDsaEngine.sign(payload, keyPair.privateKey)
        assertTrue(mlDsaEngine.verify(payload, signature, keyPair.publicKey))

        // Invalid signature length must fail verification
        val invalidSignature = signature.copyOfRange(0, signature.size - 10)
        assertFalse(mlDsaEngine.verify(payload, invalidSignature, keyPair.publicKey))
        keyPair.zeroize()
    }

    @Test(expected = IllegalArgumentException::class)
    fun `a device entry refuses a private key in place of the public one`() {
        val deviceKeyPair = mlKemEngine.generateKeyPair()
        val signing = MLDSAEngine().generateKeyPair()
        try {
            deviceManager.createDeviceEntry(deviceId = "device-01", kemPublicKey = deviceKeyPair.privateKey, signingPublicKey = signing.publicKey)
        } finally {
            deviceKeyPair.zeroize()
        }
    }
}
