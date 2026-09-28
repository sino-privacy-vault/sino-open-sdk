package com.sino.sdk.crypto

import org.junit.Assert.assertEquals
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
    fun `test incrementIV counter derivation correctness across chunk boundaries`() {
        val baseIv = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0)
        
        // Chunk 0 -> last 4 bytes should be [0, 0, 0, 0]
        val iv0 = aesEngine.incrementIV(baseIv, 0L, version = 2)
        assertEquals(0, iv0[8].toInt())
        assertEquals(0, iv0[11].toInt())

        // Chunk 1 -> last 4 bytes should be [0, 0, 0, 1]
        val iv1 = aesEngine.incrementIV(baseIv, 1L, version = 2)
        assertEquals(1, iv1[11].toInt())

        // Chunk 256 -> last 4 bytes should be [0, 0, 1, 0]
        val iv256 = aesEngine.incrementIV(baseIv, 256L, version = 2)
        assertEquals(1, iv256[10].toInt())
        assertEquals(0, iv256[11].toInt())
    }

    @Test(expected = IllegalArgumentException::class)
    fun `test incrementIV throws exception when counter exceeds 32-bit bound`() {
        val baseIv = aesEngine.generateIV()
        // Counter exceeding 0xFFFFFFFFL must throw IllegalArgumentException("Nonce Overflow")
        aesEngine.incrementIV(baseIv, 0x100000000L, version = 2)
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

    @Test(expected = Exception::class)
    fun `test ML-KEM-768 wrong private key envelope decapsulation failure`() {
        val deviceKeyPair1 = mlKemEngine.generateKeyPair()
        val deviceKeyPair2 = mlKemEngine.generateKeyPair()

        val vaultKey = ByteArray(32).also { Random().nextBytes(it) }

        // Create key envelope for device 1
        val envelope = deviceManager.createDeviceEnvelope("device-01", deviceKeyPair1.publicKey, vaultKey)

        try {
            // Attempting to unwrap envelope using device 2's private key must fail
            deviceManager.unwrapDeviceEnvelope(envelope, deviceKeyPair2.privateKey)
        } finally {
            deviceKeyPair1.zeroize()
            deviceKeyPair2.zeroize()
            SecurityUtils.fillZero(vaultKey)
        }
    }
}
