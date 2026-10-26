package com.sino.sdk.share

import com.sino.sdk.crypto.AESEncryptionEngine
import com.sino.sdk.crypto.HKDFEngine
import com.sino.sdk.crypto.SecurityUtils
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.OutputStream
import java.util.Base64

/**
 * Opens a Sino share link's file without a browser (SPECIFICATION §13, Share links): the secret is the link's fragment
 * (after `#`), the details and content are what `<hub>/l/<link id>/details` and `/content` serve.
 */
object ShareLinkReader {
    const val CONTENT_DOMAIN = "SINO/V1/LINK-CONTENT"
    const val DETAILS_DOMAIN = "SINO/V1/LINK-DETAILS"
    private const val CHUNK = 1024 * 1024
    private const val TAG = 16

    @Serializable
    data class Details(val format: String, val version: Int, val name: String, val mimeType: String, val size: Long, val ivBase64: String)

    private val json = Json { ignoreUnknownKeys = false }

    /** The details sealed in [sealed], opened with the link's [fragment]. */
    fun details(fragment: String, sealed: ByteArray): Details {
        require(sealed.size > 12 + TAG) { "The details are truncated" }
        val key = key(fragment, DETAILS_DOMAIN)
        try {
            val plain = AESEncryptionEngine().decrypt(sealed.copyOfRange(12, sealed.size), key, sealed.copyOfRange(0, 12))
            return json.decodeFromString(Details.serializer(), plain.decodeToString()).also {
                require(it.format == "SINO-LINK-DETAILS" && it.version == 1) { "Not a Sino link's details" }
            }
        } finally {
            SecurityUtils.fillZero(key)
        }
    }

    /** Writes the file of [content] (the link's encrypted copy) to [out], refusing one that is not [details]' size. */
    fun open(fragment: String, details: Details, content: File, out: OutputStream) {
        val key = key(fragment, CONTENT_DOMAIN)
        try {
            val iv = Base64.getDecoder().decode(details.ivBase64)
            val plain = ByteArrayOutputStream()
            content.inputStream().use { AESEncryptionEngine().decryptChunked(it, plain, key, iv, CHUNK, 2) }
            require(plain.size().toLong() == details.size) { "The link's content is not the file's length" }
            plain.writeTo(out)
        } finally {
            SecurityUtils.fillZero(key)
        }
    }

    private fun key(fragment: String, domain: String): ByteArray {
        val secret = Base64.getUrlDecoder().decode(fragment.trim())
        require(secret.size == 32) { "Not a Sino link's secret" }
        try {
            return HKDFEngine().extractAndExpand(null, secret, domain.encodeToByteArray(), 32)
        } finally {
            SecurityUtils.fillZero(secret)
        }
    }
}
