package com.sino.sdk.crypto

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.math.min

/**
 * HKDF-SHA-512 (RFC 5869), identical to Sino's core engine. Sino uses it without a salt and with a domain label as
 * `info`, e.g. for the recovery KEK and the device envelope keys.
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
        require(outputLength in 1..255 * HASH_LEN) { "Invalid HKDF output length" }

        // Extract: a missing or empty salt is HashLen zeros (RFC 5869); JCA rejects empty HMAC keys.
        val defaultSalt = salt == null || salt.isEmpty()
        val realSalt = if (defaultSalt) ByteArray(HASH_LEN) else salt!!
        val prk = try {
            hmacSha512(realSalt, ikm)
        } finally {
            if (defaultSalt) realSalt.fill(0)
        }

        try {
            val okm = ByteArray(outputLength)
            val t = ByteArray(HASH_LEN)
            var tLen = 0
            var loc = 0
            val n = (outputLength + HASH_LEN - 1) / HASH_LEN

            for (i in 1..n) {
                val macInput = t.copyOf(tLen) + info + i.toByte()
                val stepT = hmacSha512(prk, macInput)
                macInput.fill(0)
                stepT.copyInto(t)
                tLen = stepT.size

                val copyLen = min(outputLength - loc, HASH_LEN)
                stepT.copyInto(okm, loc, 0, copyLen)
                loc += copyLen
                stepT.fill(0)
            }
            t.fill(0)
            return okm
        } finally {
            prk.fill(0)
        }
    }

    /** HKDF-SHA-512 without a salt, domain-separated by [info] (Sino's `deriveKey`). */
    fun derive(secret: ByteArray, info: String, outputLength: Int = 32): ByteArray {
        require(secret.isNotEmpty()) { "HKDF input key material is empty" }
        val infoBytes = info.encodeToByteArray()
        return try {
            extractAndExpand(null, secret, infoBytes, outputLength)
        } finally {
            infoBytes.fill(0)
        }
    }
}
