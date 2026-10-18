package com.sino.sdk.crypto

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import org.junit.Assert.*
import org.junit.Test
import java.security.SecureRandom

class OpenSdkPqcTest {

    private val random = SecureRandom()

    private fun vectors(name: String): List<JsonObject> =
        Json.parseToJsonElement(javaClass.getResource("/acvp/$name.json")!!.readText()).jsonObject["testGroups"]!!.jsonArray
            .flatMap { it.jsonObject["tests"]!!.jsonArray.map { t -> t.jsonObject } }

    private fun JsonObject.hex(key: String): ByteArray = SecurityUtils.fromHex(this[key]!!.jsonPrimitive.content.toCharArray())

    @Test
    fun `HKDF-SHA-512 matches BouncyCastle for any salt, info and length`() {
        val hkdf = HKDFEngine()
        repeat(50) { round ->
            val ikm = ByteArray(1 + random.nextInt(64)).also { random.nextBytes(it) }
            val salt = if (round % 3 == 0) null else ByteArray(random.nextInt(80)).also { random.nextBytes(it) }
            val info = ByteArray(random.nextInt(40)).also { random.nextBytes(it) }
            val length = 1 + random.nextInt(200)
            val expected = ByteArray(length)
            HKDFBytesGenerator(SHA512Digest()).apply { init(HKDFParameters(ikm, salt, info)) }.generateBytes(expected, 0, length)
            assertArrayEquals(expected, hkdf.extractAndExpand(salt, ikm, info, length))
        }
        assertThrows(IllegalArgumentException::class.java) { hkdf.extractAndExpand(null, ByteArray(32), ByteArray(0), 0) }
    }

    @Test
    fun `ML-KEM-768 keys from a d-z seed match the NIST ACVP vectors`() {
        val engine = MLKEMEngine()
        val tests = vectors("ML-KEM-keyGen-FIPS203")
        assertTrue(tests.isNotEmpty())
        tests.forEach { t ->
            val pair = engine.keyPairFromSeed(t.hex("d") + t.hex("z"))
            assertArrayEquals(t.hex("ek"), pair.publicKey)
            assertArrayEquals(t.hex("dk"), pair.privateKey)
        }
    }

    @Test
    fun `ML-DSA-65 keys from a seed match the NIST ACVP vectors`() {
        val engine = MLDSAEngine()
        val tests = vectors("ML-DSA-keyGen-FIPS204")
        assertTrue(tests.isNotEmpty())
        tests.forEach { t ->
            val pair = engine.keyPairFromSeed(t.hex("seed"))
            assertArrayEquals(t.hex("pk"), pair.publicKey)
            assertArrayEquals(t.hex("sk"), pair.privateKey)
        }
    }

    @Test
    fun `ML-KEM-768 encapsulation round-trips with the expanded key and with the seed`() {
        val engine = MLKEMEngine()
        val seed = ByteArray(MLKEMEngine.SEED_SIZE).also { random.nextBytes(it) }
        val keyPair = engine.keyPairFromSeed(seed)
        assertEquals(MLKEMEngine.PUBLIC_KEY_SIZE, keyPair.publicKey.size)
        assertEquals(MLKEMEngine.PRIVATE_KEY_SIZE, keyPair.privateKey.size)

        val (ciphertext, secret) = engine.encapsulate(keyPair.publicKey)
        assertEquals(MLKEMEngine.CIPHERTEXT_SIZE, ciphertext.size)
        assertEquals(MLKEMEngine.SHARED_SECRET_SIZE, secret.size)
        assertArrayEquals(secret, engine.decapsulate(ciphertext, keyPair.privateKey))
        assertArrayEquals(secret, engine.decapsulate(ciphertext, seed))

        // A different key decapsulates to an unrelated secret (implicit rejection), never the same one.
        assertFalse(secret.contentEquals(engine.decapsulate(ciphertext, engine.generateKeyPair().privateKey)))
    }

    @Test
    fun `ML-DSA-65 verifies only the signed message under the signer's key`() {
        val engine = MLDSAEngine()
        val keyPair = engine.generateKeyPair()
        val message = "sino-open-sdk-pqc-manifest-test-data".encodeToByteArray()
        val signature = engine.sign(message, keyPair.privateKey)

        assertEquals(MLDSAEngine.SIGNATURE_SIZE, signature.size)
        assertTrue(engine.verify(message, signature, keyPair.publicKey))
        assertFalse(engine.verify(message + 0, signature, keyPair.publicKey))
        assertFalse(engine.verify(message, signature, engine.generateKeyPair().publicKey))
        assertFalse(engine.verify(message, signature.copyOf().also { it[100] = (it[100] + 1).toByte() }, keyPair.publicKey))
        assertFalse("A garbage key is a false, not an exception", engine.verify(message, signature, ByteArray(MLDSAEngine.PUBLIC_KEY_SIZE)))
    }

    @Test
    fun `a device entry holds the device's public keys and no copy of the vault key`() {
        val manager = DeviceKeyManager()
        val kem = MLKEMEngine().generateKeyPair()
        val signing = MLDSAEngine().generateKeyPair()

        val entry = manager.createDeviceEntry(deviceId = "device-1", kemPublicKey = kem.publicKey, signingPublicKey = signing.publicKey)
        assertEquals("device-1", entry.keyId)
        assertEquals(CryptoConstants.CRYPTO_SUITE_V1, entry.cryptoSuite)
        assertArrayEquals(kem.publicKey, SecurityUtils.fromBase64(entry.kemPublicKeyBase64.toCharArray()))
        assertArrayEquals(signing.publicKey, SecurityUtils.fromBase64(entry.signingPublicKeyBase64.toCharArray()))
        assertEquals(setOf("version", "cryptoSuite", "keyId", "deviceInfoBase64", "kemPublicKeyBase64", "signingPublicKeyBase64", "createdAt"),
            kotlinx.serialization.json.Json.parseToJsonElement(entry.toJson()).let { it as kotlinx.serialization.json.JsonObject }.keys)
        assertThrows(IllegalArgumentException::class.java) { manager.createDeviceEntry("device-1", ByteArray(16), signing.publicKey) }
        assertThrows(IllegalArgumentException::class.java) { manager.createDeviceEntry(" ", kem.publicKey, signing.publicKey) }
    }

    @Test
    fun `a device's name and type are sealed under the vault key and bound to the device`() {
        val device = MLKEMEngine().generateKeyPair()
        val signing = MLDSAEngine().generateKeyPair()
        val vaultKey = ByteArray(32).also { random.nextBytes(it) }
        val envelope = DeviceKeyManager().createDeviceEntry("device-1", device.publicKey, signing.publicKey, vaultKey, "ADA-LAPTOP", "Windows desktop")
        assertFalse(envelope.toJson().contains("ADA-LAPTOP"))

        com.sino.sdk.vault.VaultKeys(vaultKey).use { keys ->
            assertEquals(DeviceInfo("device-1", "ADA-LAPTOP", "Windows desktop"), keys.openDeviceInfo(envelope))
            assertNull(keys.openDeviceInfo(envelope.copy(keyId = "device-2")))
            val short = keys.sealDeviceInfo(DeviceInfo("device-1", "PC"))
            assertEquals("The sealed size does not give the name's length", envelope.deviceInfoBase64!!.length, short.length)
        }
        com.sino.sdk.vault.VaultKeys(ByteArray(32) { 1 }).use { assertNull(it.openDeviceInfo(envelope)) }
        assertNull(DeviceKeyManager().createDeviceEntry("device-1", device.publicKey, signing.publicKey, vaultKey).deviceInfoBase64)
    }

    @Test
    fun `manifests are encoded with every field, so signatures cover the defaults`() {
        val manifest = VaultManifest(vaultIdentifier = "v", createdAt = 1)
        val json = manifest.toJson()
        listOf("\"format\"", "\"version\"", "\"cryptoSuite\"", "\"keyEpoch\"", "\"revokedKeyIds\"", "\"mldsaSignatureBase64\"").forEach {
            assertTrue("$it missing from $json", it in json)
        }
        assertEquals(manifest, VaultManifest.fromJson(json))
        assertThrows("Unknown fields are rejected", Exception::class.java) { VaultManifest.fromJson(json.dropLast(1) + ",\"extra\":1}") }
    }
}
