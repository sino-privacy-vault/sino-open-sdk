package com.sino.sdk.crypto

import java.util.Base64

class VaultMigrationEngine(
    private val deviceKeyManager: DeviceKeyManager = DeviceKeyManager(),
    private val mlDsaEngine: MLDSAEngine = MLDSAEngine()
) {

    data class MigrationResult(
        val isMigrated: Boolean,
        val updatedManifest: VaultManifest
    )

    fun migrateVault(
        manifest: VaultManifest,
        existingVaultKey: ByteArray,
        deviceId: String,
        deviceMlKemPublicKey: ByteArray,
        signerPrivateKey: ByteArray,
        deviceName: String? = null,
        deviceType: String? = null
    ): MigrationResult {
        if (manifest.cryptoSuite == "SINO-VAULT-V1-AES256GCM-HKDFSHA512-MLKEM768") {
            return MigrationResult(isMigrated = false, updatedManifest = manifest)
        }

        val envelope = deviceKeyManager.createDeviceEnvelope(
            deviceId = deviceId,
            vaultKey = existingVaultKey,
            mlKemPublicKey = deviceMlKemPublicKey,
            deviceName = deviceName,
            deviceType = deviceType
        )

        val updatedEnvelopes = manifest.keyEnvelopes.filterNot { it.keyId == deviceId } + envelope

        val unsignedManifest = manifest.copy(
            cryptoSuite = "SINO-VAULT-V1-AES256GCM-HKDFSHA512-MLKEM768",
            keyEnvelopes = updatedEnvelopes,
            mldsaSignatureBase64 = null,
            signerKeyId = deviceId
        )

        val payload = unsignedManifest.toJson().encodeToByteArray()
        val signature = mlDsaEngine.sign(payload, signerPrivateKey)
        payload.fill(0)

        val signatureB64 = Base64.getEncoder().encodeToString(signature)
        signature.fill(0)

        val finalManifest = unsignedManifest.copy(mldsaSignatureBase64 = signatureB64)
        return MigrationResult(isMigrated = true, updatedManifest = finalManifest)
    }
}
