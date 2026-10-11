package com.sino.sdk.crypto

/**
 * Device key envelopes, identical to Sino's core: the vault root key is sealed for one device with AES-256-GCM under
 * `HKDF-SHA-512(sharedSecret, "SINO/V1/DEVICE-ENVELOPE|<suite>|<deviceId>")`, where the shared secret comes from
 * ML-KEM-768 encapsulation to the device's public key. Binding the device id and suite means an envelope cannot be
 * replayed into another device's slot or another suite.
 */
class DeviceKeyManager(
    private val mlKemEngine: MLKEMEngine = MLKEMEngine(),
    private val encryptionEngine: AESEncryptionEngine = AESEncryptionEngine(),
    private val hkdf: HKDFEngine = HKDFEngine(),
) {
    companion object {
        const val ENVELOPE_VERSION = 1
    }

    fun createDeviceEnvelope(
        deviceId: String,
        vaultKey: ByteArray,
        mlKemPublicKey: ByteArray,
        deviceName: String? = null,
        deviceType: String? = null,
        createdAt: Long = System.currentTimeMillis(),
    ): KeyEnvelope {
        require(deviceId.isNotBlank()) { "Device id is blank" }
        require(vaultKey.size == CryptoConstants.AES_KEY_SIZE) { "Vault key must be ${CryptoConstants.AES_KEY_SIZE} bytes" }

        val (ciphertext, sharedSecret) = mlKemEngine.encapsulate(mlKemPublicKey)
        var wrapKey: ByteArray? = null
        var iv: ByteArray? = null
        var encryptedVaultKey: ByteArray? = null
        try {
            wrapKey = envelopeKey(sharedSecret, deviceId)
            iv = encryptionEngine.generateIV()
            encryptedVaultKey = encryptionEngine.encrypt(vaultKey, wrapKey, iv)
            return KeyEnvelope(
                version = ENVELOPE_VERSION,
                cryptoSuite = CryptoConstants.CRYPTO_SUITE_V1,
                keyId = deviceId,
                deviceName = deviceName,
                deviceType = deviceType,
                ciphertextBase64 = SecurityUtils.toBase64(encryptedVaultKey).concatToString(),
                nonceBase64 = SecurityUtils.toBase64(iv).concatToString(),
                authTagBase64 = "",
                pqcEncapsulationBase64 = SecurityUtils.toBase64(ciphertext).concatToString(),
                createdAt = createdAt,
            )
        } finally {
            SecurityUtils.fillZero(sharedSecret)
            SecurityUtils.fillZero(wrapKey)
            SecurityUtils.fillZero(encryptedVaultKey)
            SecurityUtils.fillZero(iv)
            SecurityUtils.fillZero(ciphertext)
        }
    }

    /** The vault key sealed in [envelope], for the device holding [mlKemPrivateKey] (expanded key or 64-byte seed). */
    fun unwrapDeviceEnvelope(envelope: KeyEnvelope, mlKemPrivateKey: ByteArray): ByteArray {
        require(envelope.version == ENVELOPE_VERSION) { "Unsupported key envelope version ${envelope.version}" }
        require(envelope.cryptoSuite == CryptoConstants.CRYPTO_SUITE_V1) { "Key envelope uses an unsupported crypto suite" }
        val encapsulation = envelope.pqcEncapsulationBase64 ?: throw IllegalArgumentException("Missing PQC encapsulation")

        var ciphertext: ByteArray? = null
        var iv: ByteArray? = null
        var encryptedVaultKey: ByteArray? = null
        var sharedSecret: ByteArray? = null
        var wrapKey: ByteArray? = null
        try {
            ciphertext = SecurityUtils.fromBase64(encapsulation.toCharArray())
            iv = SecurityUtils.fromBase64(envelope.nonceBase64.toCharArray())
            encryptedVaultKey = SecurityUtils.fromBase64(envelope.ciphertextBase64.toCharArray())
            sharedSecret = mlKemEngine.decapsulate(ciphertext, mlKemPrivateKey)
            wrapKey = envelopeKey(sharedSecret, envelope.keyId)
            return encryptionEngine.decrypt(encryptedVaultKey, wrapKey, iv)
        } finally {
            SecurityUtils.fillZero(ciphertext)
            SecurityUtils.fillZero(iv)
            SecurityUtils.fillZero(encryptedVaultKey)
            SecurityUtils.fillZero(sharedSecret)
            SecurityUtils.fillZero(wrapKey)
        }
    }

    private fun envelopeKey(sharedSecret: ByteArray, deviceId: String): ByteArray =
        hkdf.derive(sharedSecret, "SINO/V1/DEVICE-ENVELOPE|${CryptoConstants.CRYPTO_SUITE_V1}|$deviceId", 32)
}
