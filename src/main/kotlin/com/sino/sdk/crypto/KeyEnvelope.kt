package com.sino.sdk.crypto

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/** Constants shared with Sino's core. */
object CryptoConstants {
    const val CRYPTO_SUITE_V1 = "SINO-VAULT-V1-AES256GCM-HKDFSHA512-MLKEM768-MLDSA65"
    const val PLAIN_CHUNK_SIZE = 1024 * 1024
    const val GCM_TAG_SIZE = 16
    const val GCM_IV_SIZE = 12
    const val AES_KEY_SIZE = 32
    const val CHUNK_FORMAT_VERSION = 2
}

/**
 * A device's entry in the signed device list. It holds no key material that opens the vault, only the device's public
 * keys: [kemPublicKeyBase64] (ML-KEM-768) and [signingPublicKeyBase64] (ML-DSA-65), which Sino uses for wrong-password
 * alerts between devices. [deviceInfoBase64] is the device's [DeviceInfo], sealed under a vault-root key (see
 * [com.sino.sdk.vault.VaultKeys.openDeviceInfo]).
 */
@Serializable
data class KeyEnvelope(
    val version: Int = 2,
    val cryptoSuite: String = CryptoConstants.CRYPTO_SUITE_V1,
    val keyId: String,
    val deviceInfoBase64: String? = null,
    val kemPublicKeyBase64: String,
    val signingPublicKeyBase64: String,
    val createdAt: Long,
) {
    fun toJson(): String = CryptoJson.encodeToString(serializer(), this)

    companion object {
        fun fromJson(json: String): KeyEnvelope = CryptoJson.decodeFromString(serializer(), json)
    }
}

/** A device's name and type as Sino shows them. [keyId] binds it to the envelope it is sealed in. */
@Serializable
data class DeviceInfo(val keyId: String, val name: String? = null, val type: String? = null) {
    fun toJson(): String = CryptoJson.encodeToString(serializer(), this)

    companion object {
        fun fromJson(json: String): DeviceInfo = CryptoJson.decodeFromString(serializer(), json)
    }
}

/**
 * The real vault's signed device list (`SinoVault/security/vault_manifest.json`). Signed with ML-DSA-65 over
 * [toJson] of the manifest with [mldsaSignatureBase64] set to null; see [com.sino.sdk.vault.ManifestVerifier].
 */
@Serializable
data class VaultManifest(
    val format: String = FORMAT,
    val version: Int = CURRENT_VERSION,
    val cryptoSuite: String = CryptoConstants.CRYPTO_SUITE_V1,
    val keyEpoch: Int = 1,
    val vaultIdentifier: String,
    val keyEnvelopes: List<KeyEnvelope> = emptyList(),
    /** Devices explicitly revoked: each wipes itself when it next reads a list that verifies. */
    val revokedKeyIds: List<String> = emptyList(),
    val mldsaSignatureBase64: String? = null,
    val signerKeyId: String? = null,
    val createdAt: Long,
) {
    fun toJson(): String = CryptoJson.encodeToString(serializer(), this)

    companion object {
        const val FORMAT = "SINO-VAULT"
        const val CURRENT_VERSION = 1

        fun fromJson(json: String): VaultManifest = CryptoJson.decodeFromString(serializer(), json)
    }
}

/**
 * The encoding Sino signs: every field written (defaults included), in declaration order, unknown fields rejected.
 * Any other encoding of the same manifest produces different bytes and fails signature verification.
 */
internal val CryptoJson = Json { encodeDefaults = true }
