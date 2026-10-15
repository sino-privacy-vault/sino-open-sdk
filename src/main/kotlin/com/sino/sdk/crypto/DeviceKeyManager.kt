package com.sino.sdk.crypto

import com.sino.sdk.vault.VaultKeys

/**
 * Device-list entries, identical to Sino's core: a device's id, its ML-KEM-768 and ML-DSA-65 public keys, and its
 * name and type sealed with [VaultKeys.sealDeviceInfo] under the vault key's domain key. An entry holds no copy of the
 * vault key (a device keeps its private keys while locked, so such a copy would open the vault without the password).
 */
class DeviceKeyManager {
    companion object {
        const val ENVELOPE_VERSION = 2
    }

    /** [vaultKey] seals [deviceName] and [deviceType]; it is needed only when one of them is given. */
    fun createDeviceEntry(
        deviceId: String,
        kemPublicKey: ByteArray,
        signingPublicKey: ByteArray,
        vaultKey: ByteArray? = null,
        deviceName: String? = null,
        deviceType: String? = null,
        createdAt: Long = System.currentTimeMillis(),
    ): KeyEnvelope {
        require(deviceId.isNotBlank()) { "Device id is blank" }
        require(kemPublicKey.size == MLKEMEngine.PUBLIC_KEY_SIZE) { "Not an ML-KEM-768 public key" }
        require(signingPublicKey.size == MLDSAEngine.PUBLIC_KEY_SIZE) { "Not an ML-DSA-65 public key" }
        val deviceInfo = if (deviceName == null && deviceType == null) null else {
            requireNotNull(vaultKey) { "The vault key seals the device's name" }
            VaultKeys(vaultKey).use { it.sealDeviceInfo(DeviceInfo(deviceId, deviceName, deviceType)) }
        }
        return KeyEnvelope(
            version = ENVELOPE_VERSION,
            cryptoSuite = CryptoConstants.CRYPTO_SUITE_V1,
            keyId = deviceId,
            deviceInfoBase64 = deviceInfo,
            kemPublicKeyBase64 = SecurityUtils.toBase64(kemPublicKey).concatToString(),
            signingPublicKeyBase64 = SecurityUtils.toBase64(signingPublicKey).concatToString(),
            createdAt = createdAt,
        )
    }
}
