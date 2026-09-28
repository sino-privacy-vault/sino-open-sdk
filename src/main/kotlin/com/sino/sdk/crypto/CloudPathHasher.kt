package com.sino.sdk.crypto

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Open Specification for Sino's Cloud Path Anonymization.
 * Converts readable folder paths (e.g. "DCIM/Vacation/photo.jpg") into opaque,
 * deterministic hashes using HMAC-SHA256 with a salt to ensure complete "Cloud Blindness".
 * Hardened v4: 128-bit namespace truncation (32 hex chars) and zero-string memory sanitization.
 */
class CloudPathHasher {

    companion object {
        private const val HMAC_ALGORITHM = "HmacSHA256"
        
        /**
         * Standard truncation length for anonymized cloud folders and deterministic filenames (128-bit namespace).
         */
        const val PATH_TRUNCATION_LENGTH = 32

        /**
         * Standard truncation length for metadata batch identifiers (128-bit namespace).
         */
        const val BATCH_TRUNCATION_LENGTH = 32

        /**
         * Computes an opaque, deterministic cloud folder hash.
         * Used for constructing remote directory structures.
         */
        fun computeCloudFolderHash(fullRelativePath: String, pathSalt: ByteArray): String {
            return hashPathAndTruncate(fullRelativePath, pathSalt, PATH_TRUNCATION_LENGTH)
        }

        /**
         * Computes an opaque, deterministic cloud filename.
         * Used for content-addressable storage and multi-device consensus.
         */
        fun computeCloudFileHash(fileChecksum: String, pathSalt: ByteArray): String {
            return hashPathAndTruncate(fileChecksum, pathSalt, PATH_TRUNCATION_LENGTH)
        }

        /**
         * Computes the obfuscated name for a metadata batch file.
         */
        fun computeMetadataBatchHash(folderId: Long, pathSalt: ByteArray): String {
            val base = "folder_metadata_$folderId"
            val hash = hashPathAndTruncate(base, pathSalt, BATCH_TRUNCATION_LENGTH)
            return "$hash.batch"
        }

        /**
         * Internal helper to compute HMAC-SHA256 hash and return sliced String with immediate zero-filling.
         */
        private fun hashPathAndTruncate(input: String, pathSalt: ByteArray, length: Int): String {
            val normalized = input.trim().replace('\\', '/')
            val mac = Mac.getInstance(HMAC_ALGORITHM)
            val keySpec = SecretKeySpec(pathSalt, HMAC_ALGORITHM)
            mac.init(keySpec)

            val hashBytes = mac.doFinal(normalized.toByteArray(Charsets.UTF_8))
            val hexChars = SecurityUtils.toHex(hashBytes)
            val targetLen = minOf(length, hexChars.size)
            val result = String(hexChars, 0, targetLen)
            SecurityUtils.fillZero(hexChars)
            return result
        }
    }
}
