package com.sino.sdk.crypto

import org.junit.Assert.*
import org.junit.Test

class OpenSdkPqcTest {

    @Test
    fun testHkdfSha512DomainSeparation() {
        val hkdfEngine = HKDFEngine()
        val rootKey = ByteArray(32) { (it + 1).toByte() }

        val vaultKey1 = hkdfEngine.deriveVaultKey(rootKey)
        val vaultKey2 = hkdfEngine.deriveVaultKey(rootKey)
        val fileKey1 = hkdfEngine.deriveFileKey(vaultKey1, 1001L)
        val fileKey2 = hkdfEngine.deriveFileKey(vaultKey1, 1002L)

        assertEquals(32, vaultKey1.size)
        assertEquals(32, fileKey1.size)
        assertEquals(32, fileKey2.size)

        assertArrayEquals(vaultKey1, vaultKey2)
        assertFalse(fileKey1.contentEquals(fileKey2))
    }

    @Test
    fun testMlKemEncapsulationAndDecapsulation() {
        val mlKemEngine = MLKEMEngine()
        val keyPair = mlKemEngine.generateKeyPair()

        assertEquals(MLKEMEngine.PUBLIC_KEY_SIZE, keyPair.publicKey.size)
        assertEquals(MLKEMEngine.PRIVATE_KEY_SIZE, keyPair.privateKey.size)

        val (ciphertext, sharedSecretEnc) = mlKemEngine.encapsulate(keyPair.publicKey)
        assertEquals(MLKEMEngine.CIPHERTEXT_SIZE, ciphertext.size)
        assertEquals(MLKEMEngine.SHARED_SECRET_SIZE, sharedSecretEnc.size)

        val sharedSecretDec = mlKemEngine.decapsulate(ciphertext, keyPair.privateKey)
        assertArrayEquals(sharedSecretEnc, sharedSecretDec)

        keyPair.zeroize()
    }

    @Test
    fun testMlDsaSigningAndVerification() {
        val mlDsaEngine = MLDSAEngine()
        val keyPair = mlDsaEngine.generateKeyPair()

        val message = "sino-open-sdk-pqc-manifest-test-data".encodeToByteArray()
        val signature = mlDsaEngine.sign(message, keyPair.privateKey)

        assertEquals(MLDSAEngine.SIGNATURE_SIZE, signature.size)
        assertTrue(mlDsaEngine.verify(message, signature, keyPair.publicKey))

        keyPair.zeroize()
    }

    @Test
    fun testDeviceKeyEnvelopeCreationAndUnwrap() {
        val deviceManager = DeviceKeyManager()
        val mlKemEngine = MLKEMEngine()
        val keyPair = mlKemEngine.generateKeyPair()
        val vaultKey = ByteArray(32) { 7 }

        val envelope = deviceManager.createDeviceEnvelope(
            deviceId = "sdk-test-device-1",
            vaultKey = vaultKey,
            mlKemPublicKey = keyPair.publicKey
        )

        assertEquals("sdk-test-device-1", envelope.keyId)

        val unwrappedSecret = deviceManager.unwrapDeviceEnvelope(envelope, keyPair.privateKey)
        assertArrayEquals(vaultKey, unwrappedSecret)

        val envelopes = listOf(envelope)
        val revoked = deviceManager.revokeDevice(envelopes, "sdk-test-device-1")
        assertTrue(revoked.isEmpty())

        keyPair.zeroize()
    }

    @Test
    fun testVaultMigrationEngine() {
        val migrationEngine = VaultMigrationEngine()
        val mlKemEngine = MLKEMEngine()
        val mlDsaEngine = MLDSAEngine()

        val mlKemKeyPair = mlKemEngine.generateKeyPair()
        val mlDsaKeyPair = mlDsaEngine.generateKeyPair()
        val vaultKey = ByteArray(32) { 5 }

        val legacyManifest = VaultManifest(
            cryptoSuite = "SINO-LEGACY-V0",
            vaultIdentifier = "sdk-vault-legacy-1",
            createdAt = 1000L
        )

        val result = migrationEngine.migrateVault(
            manifest = legacyManifest,
            existingVaultKey = vaultKey,
            deviceId = "migrated-device-1",
            deviceMlKemPublicKey = mlKemKeyPair.publicKey,
            signerPrivateKey = mlDsaKeyPair.privateKey
        )

        assertTrue(result.isMigrated)
        assertEquals("SINO-VAULT-V1-AES256GCM-HKDFSHA512-MLKEM768", result.updatedManifest.cryptoSuite)
        assertEquals(1, result.updatedManifest.keyEnvelopes.size)
        assertNotNull(result.updatedManifest.mldsaSignatureBase64)

        // Verify JSON roundtrip
        val jsonStr = result.updatedManifest.toJson()
        val parsedStr = VaultManifest.fromJson(jsonStr)
        assertEquals(result.updatedManifest, parsedStr)

        mlKemKeyPair.zeroize()
        mlDsaKeyPair.zeroize()
    }
}
