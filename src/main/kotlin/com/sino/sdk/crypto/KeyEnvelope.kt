package com.sino.sdk.crypto

import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

@Serializable
data class KeyEnvelope(
    val version: Int = 1,
    val cryptoSuite: String = "SINO-VAULT-V1-AES256GCM-HKDFSHA512-MLKEM768",
    val keyId: String,
    val deviceName: String? = null,
    val deviceType: String? = null,
    val ciphertextBase64: String,
    val nonceBase64: String,
    val authTagBase64: String,
    val pqcEncapsulationBase64: String? = null,
    val createdAt: Long
) {
    fun toJson(): String = Json.encodeToString(serializer(), this)

    companion object {
        fun fromJson(jsonStr: String): KeyEnvelope = Json.decodeFromString(serializer(), jsonStr)
    }
}

@Serializable
data class VaultManifest(
    val format: String = "SINO-VAULT",
    val version: Int = 1,
    val cryptoSuite: String = "SINO-VAULT-V1-AES256GCM-HKDFSHA512-MLKEM768",
    val keyEpoch: Int = 1,
    val vaultIdentifier: String,
    val keyEnvelopes: List<KeyEnvelope> = emptyList(),
    val mldsaSignatureBase64: String? = null,
    val signerKeyId: String? = null,
    val createdAt: Long
) {
    fun toJson(): String = Json.encodeToString(serializer(), this)

    companion object {
        fun fromJson(jsonStr: String): VaultManifest = Json.decodeFromString(serializer(), jsonStr)
    }
}
