package com.sino.sdk.vault

import com.sino.sdk.crypto.MLDSAEngine
import com.sino.sdk.crypto.SecurityUtils
import com.sino.sdk.crypto.VaultManifest

/**
 * Checks a vault's signed device list the way Sino's devices do: it must be a Sino manifest for [expectedVaultId],
 * at a key epoch of at least [minKeyEpoch], with an ML-DSA-65 signature by [signerPublicKey] over the manifest's
 * JSON with the signature field cleared. With the vault root, [forVault] derives the expected signer and id.
 */
class ManifestVerifier(
    private val signerPublicKey: ByteArray,
    private val expectedVaultId: String,
    private val minKeyEpoch: Int = 0,
    private val mlDsa: MLDSAEngine = MLDSAEngine(),
) {
    /** Any malformed input yields false. */
    fun verifies(manifest: VaultManifest): Boolean {
        if (manifest.format != VaultManifest.FORMAT) return false
        if (manifest.vaultIdentifier != expectedVaultId) return false
        if (manifest.keyEpoch < minKeyEpoch) return false
        val signatureChars = (manifest.mldsaSignatureBase64 ?: return false).toCharArray()
        val signature = try {
            SecurityUtils.fromBase64(signatureChars)
        } catch (e: IllegalArgumentException) {
            return false
        } finally {
            SecurityUtils.fillZero(signatureChars)
        }
        val payload = manifest.copy(mldsaSignatureBase64 = null).toJson().encodeToByteArray()
        return mlDsa.verify(payload, signature, signerPublicKey)
    }

    companion object {
        fun forVault(keys: VaultKeys, minKeyEpoch: Int = 0): ManifestVerifier {
            val signer = keys.manifestSigner()
            return try {
                ManifestVerifier(signer.publicKey.copyOf(), keys.vaultIdentifier(), minKeyEpoch)
            } finally {
                signer.zeroize()
            }
        }
    }
}
