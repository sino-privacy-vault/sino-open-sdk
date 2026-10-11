package com.sino.sdk.vault

import com.sino.sdk.crypto.AESEncryptionEngine
import com.sino.sdk.crypto.CryptoConstants
import com.sino.sdk.crypto.MLDSAEngine
import com.sino.sdk.crypto.SecurityUtils
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Everything Sino derives from a vault's root key (RMK), identical on every platform:
 * - **domain keys**: `HMAC-SHA256(RMK, utf8(domain) || 0x01)` (one HKDF-Expand block);
 * - **file keys (DEKs)**: random per file, stored wrapped as `base64(iv(12) || AES-256-GCM(DEK, RMK))`;
 * - the **manifest signer**: the ML-DSA-65 key pair of the seed `domainKey("SINO/V1/VAULT-MANIFEST-SIGNER")`;
 * - the **vault identifier**: hex of the first 16 bytes of `domainKey("SINO/V1/VAULT-MANIFEST-ID")`.
 *
 * Only the real vault's root can be recovered: the decoy vault's root is derived from a hardware-sealed key of one
 * device and never leaves it, by design.
 */
class VaultKeys(rootKey: ByteArray) : AutoCloseable {

    private val rmk: ByteArray = rootKey.copyOf()
    private val aes = AESEncryptionEngine()

    init {
        require(rmk.size == CryptoConstants.AES_KEY_SIZE) { "The vault root key must be ${CryptoConstants.AES_KEY_SIZE} bytes" }
    }

    fun domainKey(domain: String): ByteArray = Mac.getInstance("HmacSHA256").run {
        init(SecretKeySpec(rmk, "HmacSHA256"))
        update(domain.toByteArray(Charsets.UTF_8))
        update(0x01.toByte())
        doFinal()
    }

    /** The key sealing the real vault's folder metadata batches. */
    fun metadataBatchKey(): ByteArray = domainKey(BATCH_KEY_DOMAIN)

    /** A file's DEK from its wrapped form (`MediaMetadata.encryptedDEK`); throws if it was not wrapped by this vault. */
    fun unwrapDek(wrapped: String): ByteArray {
        val chars = wrapped.toCharArray()
        val data = try {
            SecurityUtils.fromBase64(chars)
        } finally {
            SecurityUtils.fillZero(chars)
        }
        try {
            require(data.size > IV_SIZE + CryptoConstants.GCM_TAG_SIZE) { "Wrapped DEK is too short" }
            val dek = aes.decrypt(data.copyOfRange(IV_SIZE, data.size), rmk, data.copyOfRange(0, IV_SIZE))
            require(dek.size == CryptoConstants.AES_KEY_SIZE) { "Wrapped DEK has an invalid size" }
            return dek
        } finally {
            SecurityUtils.fillZero(data)
        }
    }

    /** Wraps [dek] the way Sino does (fresh IV). Used to build test vaults. */
    fun wrapDek(dek: ByteArray): String {
        val iv = aes.generateIV()
        val combined = iv + aes.encrypt(dek, rmk, iv)
        val chars = SecurityUtils.toBase64(combined)
        return try {
            chars.concatToString()
        } finally {
            SecurityUtils.fillZero(chars)
            SecurityUtils.fillZero(combined)
        }
    }

    fun manifestSigner(): MLDSAEngine.KeyPair {
        val xi = domainKey(MANIFEST_SIGNER_DOMAIN)
        return try {
            MLDSAEngine().keyPairFromSeed(xi)
        } finally {
            SecurityUtils.fillZero(xi)
        }
    }

    fun vaultIdentifier(): String {
        val bytes = domainKey(MANIFEST_ID_DOMAIN)
        return try {
            SecurityUtils.toHex(bytes.copyOfRange(0, 16)).concatToString()
        } finally {
            SecurityUtils.fillZero(bytes)
        }
    }

    override fun close() = SecurityUtils.fillZero(rmk)

    companion object {
        private const val IV_SIZE = CryptoConstants.GCM_IV_SIZE
        const val BATCH_KEY_DOMAIN = "FolderMetadataBatchV1"
        const val MANIFEST_SIGNER_DOMAIN = "SINO/V1/VAULT-MANIFEST-SIGNER"
        const val MANIFEST_ID_DOMAIN = "SINO/V1/VAULT-MANIFEST-ID"
    }
}
