package com.sino.sdk.crypto

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.math.min

/**
 * Domain-separated HKDF-SHA-512 engine for sino-open-sdk with memory hygiene.
 */
class HKDFEngine {

    companion object {
        private const val HASH_LEN = 64 // SHA-512 digest size in bytes
        private const val HMAC_ALGORITHM = "HmacSHA512"

        fun hmacSha512(key: ByteArray, data: ByteArray): ByteArray {
            val mac = Mac.getInstance(HMAC_ALGORITHM)
            mac.init(SecretKeySpec(key, HMAC_ALGORITHM))
            return mac.doFinal(data)
        }
    }

    fun extractAndExpand(
        salt: ByteArray?,
        ikm: ByteArray,
        info: ByteArray,
        outputLength: Int
    ): ByteArray {
        require(outputLength <= 255 * HASH_LEN) { "HKDF output length too large" }

        val realSalt = salt ?: ByteArray(HASH_LEN) { 0 }
        val prk = try {
            hmacSha512(realSalt, ikm)
        } finally {
            if (salt == null) {
                realSalt.fill(0)
            }
        }

        try {
            val okm = ByteArray(outputLength)
            val t = ByteArray(HASH_LEN)
            var tLen = 0
            var loc = 0
            val n = (outputLength + HASH_LEN - 1) / HASH_LEN

            for (i in 1..n) {
                val macInput = if (tLen == 0) {
                    info + i.toByte()
                } else {
                    t.copyOf(tLen) + info + i.toByte()
                }
                val stepT = hmacSha512(prk, macInput)
                stepT.copyInto(t, 0, 0, stepT.size)
                tLen = stepT.size

                val copyLen = min(outputLength - loc, HASH_LEN)
                t.copyInto(okm, loc, 0, copyLen)
                loc += copyLen
                stepT.fill(0)
            }
            t.fill(0)
            return okm
        } finally {
            prk.fill(0)
        }
    }

    fun deriveVaultKey(rootMasterKey: ByteArray): ByteArray {
        val info = "SINO/V1/VAULT".encodeToByteArray()
        return extractAndExpand(salt = null, ikm = rootMasterKey, info = info, outputLength = 32)
    }

    fun deriveFileKey(vaultKey: ByteArray, fileId: Long): ByteArray {
        val info = "SINO/V1/FILE/$fileId".encodeToByteArray()
        return extractAndExpand(salt = null, ikm = vaultKey, info = info, outputLength = 32)
    }
}
