package com.sino.sdk.crypto

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.Base64

class DeviceKeyManager(
    private val mlKemEngine: MLKEMEngine = MLKEMEngine(),
    private val encryptionEngine: AESEncryptionEngine = AESEncryptionEngine()
) {

    fun createDeviceEnvelope(
        deviceId: String,
        vaultKey: ByteArray,
        mlKemPublicKey: ByteArray,
        deviceName: String? = null,
        deviceType: String? = null
    ): KeyEnvelope {
        val (ciphertext, sharedSecret) = mlKemEngine.encapsulate(mlKemPublicKey)
        val iv = encryptionEngine.generateIV()

        val inStream = ByteArrayInputStream(vaultKey)
        val outStream = ByteArrayOutputStream()
        encryptionEngine.encrypt(inStream, outStream, sharedSecret, iv)
        val encryptedVaultKey = outStream.toByteArray()

        val envelope = KeyEnvelope(
            version = 1,
            cryptoSuite = "SINO-VAULT-V1-AES256GCM-HKDFSHA512-MLKEM768",
            keyId = deviceId,
            deviceName = deviceName,
            deviceType = deviceType,
            ciphertextBase64 = Base64.getEncoder().encodeToString(encryptedVaultKey),
            nonceBase64 = Base64.getEncoder().encodeToString(iv),
            authTagBase64 = "",
            pqcEncapsulationBase64 = Base64.getEncoder().encodeToString(ciphertext),
            createdAt = System.currentTimeMillis()
        )

        sharedSecret.fill(0)
        encryptedVaultKey.fill(0)
        iv.fill(0)
        ciphertext.fill(0)

        return envelope
    }

    fun unwrapDeviceEnvelope(
        envelope: KeyEnvelope,
        mlKemPrivateKey: ByteArray
    ): ByteArray {
        val pqcBase64 = envelope.pqcEncapsulationBase64 ?: throw IllegalArgumentException("Missing PQC encapsulation")
        val ciphertext = Base64.getDecoder().decode(pqcBase64)
        val iv = Base64.getDecoder().decode(envelope.nonceBase64)
        val encryptedVaultKey = Base64.getDecoder().decode(envelope.ciphertextBase64)

        val sharedSecret = mlKemEngine.decapsulate(ciphertext, mlKemPrivateKey)

        val inStream = ByteArrayInputStream(encryptedVaultKey)
        val outStream = ByteArrayOutputStream()
        encryptionEngine.decrypt(inStream, outStream, sharedSecret, iv)
        val vaultKey = outStream.toByteArray()

        ciphertext.fill(0)
        iv.fill(0)
        encryptedVaultKey.fill(0)
        sharedSecret.fill(0)

        return vaultKey
    }

    fun revokeDevice(envelopes: List<KeyEnvelope>, deviceIdToRevoke: String): List<KeyEnvelope> {
        return envelopes.filter { it.keyId != deviceIdToRevoke }
    }
}
