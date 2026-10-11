package com.sino.sdk.vault

import com.sino.sdk.crypto.AESEncryptionEngine
import com.sino.sdk.crypto.CryptoConstants
import java.security.MessageDigest

/** Not a well-formed v2 Sino artifact, or its checksum does not match (corruption). */
class ArtifactFormatException(message: String) : IllegalArgumentException(message)

/**
 * Sino's container for small artifacts (metadata batches, the recovery backup, snapshots):
 * `"SINO" || 0x02 || iv(12) || AES-256-GCM(data) || SHA-256(everything before it)`.
 *
 * AES-GCM provides confidentiality and authenticity. The unkeyed SHA-256 only tells storage corruption apart from a
 * wrong key or tampering. Each artifact type is sealed under its own key.
 */
object ArtifactContainer {
    private val MAGIC = "SINO".encodeToByteArray()
    private const val VERSION: Byte = 2
    private const val CHECKSUM_SIZE = 32
    private val HEADER_SIZE = MAGIC.size + 1
    private val MIN_SIZE = HEADER_SIZE + CryptoConstants.GCM_IV_SIZE + CryptoConstants.GCM_TAG_SIZE + CHECKSUM_SIZE

    private val aes = AESEncryptionEngine()

    fun wrap(data: ByteArray, key: ByteArray): ByteArray {
        val iv = aes.generateIV()
        val body = MAGIC + VERSION + iv + aes.encrypt(data, key, iv)
        return body + sha256(body)
    }

    /** Checks the header and checksum ([ArtifactFormatException]), then decrypts; a wrong key fails in the AEAD. */
    fun unwrap(container: ByteArray, key: ByteArray): ByteArray {
        if (container.size < HEADER_SIZE) throw ArtifactFormatException("Invalid artifact: header missing")
        if (!container.copyOfRange(0, MAGIC.size).contentEquals(MAGIC)) throw ArtifactFormatException("Not a Sino artifact")
        val version = container[MAGIC.size]
        if (version != VERSION) throw ArtifactFormatException("Unsupported artifact version $version")
        if (container.size < MIN_SIZE) throw ArtifactFormatException("Invalid artifact: truncated")

        val contentSize = container.size - CHECKSUM_SIZE
        if (!MessageDigest.isEqual(sha256(container.copyOfRange(0, contentSize)), container.copyOfRange(contentSize, container.size))) {
            throw ArtifactFormatException("Artifact integrity failure: corrupted or tampered")
        }
        val iv = container.copyOfRange(HEADER_SIZE, HEADER_SIZE + CryptoConstants.GCM_IV_SIZE)
        return aes.decrypt(container.copyOfRange(HEADER_SIZE + CryptoConstants.GCM_IV_SIZE, contentSize), key, iv)
    }

    private fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)
}
