package com.sino.sdk.vault

import com.sino.sdk.crypto.CryptoConstants
import com.sino.sdk.crypto.HKDFEngine
import com.sino.sdk.crypto.SecurityUtils
import com.sino.sdk.crypto.SinoKeyDerivation

/**
 * Opens a vault's recovery backup with its 24-word recovery phrase, exactly as Sino does:
 * 1. the phrase is normalised (each word trimmed and lower-cased, joined by single spaces);
 * 2. `root = Argon2id(phrase, recoverySalt)` (64 MiB, 3 iterations, 4 lanes, 32 bytes), where the recovery salt is
 *    the public `security/vault_salt.public`;
 * 3. `kek = HKDF-SHA-512(root, "SINO/V1/RECOVERY-KEK")`;
 * 4. `security/rmk_backup.bin` is an [ArtifactContainer] sealed under the KEK holding `RMK(32) || vaultSalt`.
 *
 * The vault salt keys the vault's hashed cloud paths ([VaultCloudLayout]); it travels only inside the backup.
 */
class RecoveryKit(private val keyDerivation: SinoKeyDerivation = SinoKeyDerivation()) {

    /** A recovered vault. Call [close] to wipe both values. */
    class RecoveredVault(val rootKey: ByteArray, val vaultSalt: ByteArray) : AutoCloseable {
        override fun close() {
            SecurityUtils.fillZero(rootKey)
            SecurityUtils.fillZero(vaultSalt)
        }
    }

    /**
     * The key-encryption key of [phrase] under [recoverySalt]. Throws [IllegalArgumentException] unless the phrase
     * has exactly [PHRASE_WORDS] words.
     */
    fun deriveKek(phrase: List<CharArray>, recoverySalt: ByteArray): ByteArray {
        require(phrase.size == PHRASE_WORDS) { "A recovery phrase has $PHRASE_WORDS words (got ${phrase.size})" }
        require(recoverySalt.size >= MIN_SALT_SIZE) { "The recovery salt must be at least $MIN_SALT_SIZE bytes" }
        val joined = normalize(phrase)
        var root: ByteArray? = null
        try {
            root = keyDerivation.deriveKey(joined, recoverySalt)
            return HKDFEngine().derive(root, KEK_INFO, CryptoConstants.AES_KEY_SIZE)
        } finally {
            SecurityUtils.fillZero(joined)
            SecurityUtils.fillZero(root)
        }
    }

    /** Opens [backup] (`rmk_backup.bin`) with [kek]; throws if the phrase does not belong to this backup. */
    fun openBackup(backup: ByteArray, kek: ByteArray): RecoveredVault {
        val payload = try {
            ArtifactContainer.unwrap(backup, kek)
        } catch (e: ArtifactFormatException) {
            throw e
        } catch (e: Exception) {
            throw IllegalArgumentException("The recovery phrase does not match this vault's backup")
        }
        try {
            require(payload.size >= CryptoConstants.AES_KEY_SIZE + MIN_SALT_SIZE) { "The recovery backup has an invalid format" }
            return RecoveredVault(
                payload.copyOfRange(0, CryptoConstants.AES_KEY_SIZE),
                payload.copyOfRange(CryptoConstants.AES_KEY_SIZE, payload.size),
            )
        } finally {
            SecurityUtils.fillZero(payload)
        }
    }

    /** Seals a backup the way Sino does. Used to build test vaults. */
    fun sealBackup(rootKey: ByteArray, vaultSalt: ByteArray, kek: ByteArray): ByteArray {
        val sealed = rootKey + vaultSalt
        return try {
            ArtifactContainer.wrap(sealed, kek)
        } finally {
            SecurityUtils.fillZero(sealed)
        }
    }

    companion object {
        const val PHRASE_WORDS = 24
        private const val MIN_SALT_SIZE = 16
        private const val KEK_INFO = "SINO/V1/RECOVERY-KEK"
        private const val RECOVERY_SALT_INFO = "SINO/V1/RECOVERY-SALT"

        /** The public recovery salt of a vault salt (one-way). */
        fun recoverySalt(vaultSalt: ByteArray): ByteArray =
            HKDFEngine().derive(vaultSalt, RECOVERY_SALT_INFO, CryptoConstants.AES_KEY_SIZE)

        /**
         * Splits [text] into words on whitespace without creating Strings, so a phrase read from a file or console
         * can be wiped. Commas and numbering are not accepted: Sino shows the phrase as plain words.
         */
        fun splitWords(text: CharArray): List<CharArray> {
            val words = mutableListOf<CharArray>()
            var i = 0
            while (i < text.size) {
                while (i < text.size && text[i].isWhitespace()) i++
                val start = i
                while (i < text.size && !text[i].isWhitespace()) i++
                if (i > start) words.add(text.copyOfRange(start, i))
            }
            return words
        }

        private fun normalize(phrase: List<CharArray>): CharArray {
            val words = phrase.map { word ->
                var start = 0
                var end = word.size
                while (start < end && word[start].isWhitespace()) start++
                while (end > start && word[end - 1].isWhitespace()) end--
                CharArray(end - start) { word[start + it].lowercaseChar() }
            }
            try {
                val result = CharArray(words.sumOf { it.size } + words.size - 1)
                var pos = 0
                words.forEachIndexed { index, word ->
                    word.copyInto(result, pos)
                    pos += word.size
                    if (index < words.size - 1) result[pos++] = ' '
                }
                return result
            } finally {
                words.forEach { SecurityUtils.fillZero(it) }
            }
        }
    }
}
