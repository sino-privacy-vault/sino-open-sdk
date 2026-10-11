package com.sino.sdk.crypto

/**
 * Common security utilities for the Sino ecosystem: memory hygiene and String-free encoders/decoders shared by
 * all platforms. Decoders are strict and their errors never echo input characters, which may be secrets.
 */
object SecurityUtils {

    /**
     * Physically overwrites a ByteArray with zeros in the heap.
     * Use this immediately after a sensitive key or plaintext is no longer needed.
     */
    fun fillZero(array: ByteArray?) {
        array?.fill(0)
    }

    /**
     * Physically overwrites a CharArray with zeros in the heap.
     * Use this immediately after a sensitive password is no longer needed.
     */
    fun fillZero(array: CharArray?) {
        array?.fill('\u0000')
    }

    /**
     * Converts a CharArray to a UTF-8 encoded ByteArray without creating a transient String.
     * Ensures no immutable String "ghosts" remain in memory. Supports supplementary planes (e.g. emojis).
     * An unpaired surrogate is encoded as U+FFFD, so the output is always valid UTF-8.
     */
    fun toUtf8(chars: CharArray): ByteArray {
        var len = 0
        var i = 0
        while (i < chars.size) {
            val c1 = chars[i]
            if (c1.isHighSurrogate() && i + 1 < chars.size && chars[i+1].isLowSurrogate()) {
                len += 4
                i += 2
            } else {
                val code = c1.code
                len += when {
                    code < 0x80 -> 1
                    code < 0x800 -> 2
                    else -> 3
                }
                i += 1
            }
        }

        val result = ByteArray(len)
        var pos = 0
        i = 0
        while (i < chars.size) {
            val c1 = chars[i]
            if (c1.isHighSurrogate() && i + 1 < chars.size && chars[i+1].isLowSurrogate()) {
                val c2 = chars[i + 1]
                val codePoint = 0x10000 + ((c1.code and 0x3FF) shl 10) or (c2.code and 0x3FF)
                result[pos++] = (0xf0 or (codePoint shr 18)).toByte()
                result[pos++] = (0x80 or ((codePoint shr 12) and 0x3f)).toByte()
                result[pos++] = (0x80 or ((codePoint shr 6) and 0x3f)).toByte()
                result[pos++] = (0x80 or (codePoint and 0x3f)).toByte()
                i += 2
            } else {
                val code = if (c1.isSurrogate()) REPLACEMENT_CHAR else c1.code
                when {
                    code < 0x80 -> result[pos++] = code.toByte()
                    code < 0x800 -> {
                        result[pos++] = (0xc0 or (code shr 6)).toByte()
                        result[pos++] = (0x80 or (code and 0x3f)).toByte()
                    }
                    else -> {
                        result[pos++] = (0xe0 or (code shr 12)).toByte()
                        result[pos++] = (0x80 or ((code shr 6) and 0x3f)).toByte()
                        result[pos++] = (0x80 or (code and 0x3f)).toByte()
                    }
                }
                i += 1
            }
        }
        return result
    }

    /**
     * Converts a UTF-8 encoded ByteArray to a CharArray without creating a transient String.
     * Supports supplementary planes (e.g. emojis).
     *
     * Strict: truncated sequences, stray continuation bytes, overlong forms, encoded surrogates and code points
     * above U+10FFFF throw [IllegalArgumentException] (never an index error, never silently altered text).
     * The message never contains the input.
     */
    fun fromUtf8(bytes: ByteArray): CharArray {
        // UTF-16 never needs more chars than UTF-8 has bytes.
        val scratch = CharArray(bytes.size)
        var pos = 0
        var i = 0
        try {
            while (i < bytes.size) {
                val b1 = bytes[i].toInt() and 0xFF
                when {
                    b1 < 0x80 -> {
                        scratch[pos++] = b1.toChar()
                        i += 1
                    }
                    b1 in 0xC2..0xDF -> {
                        val b2 = continuation(bytes, i + 1, 0x80, 0xBF)
                        scratch[pos++] = (((b1 and 0x1F) shl 6) or b2).toChar()
                        i += 2
                    }
                    b1 in 0xE0..0xEF -> {
                        // E0: no overlong forms; ED: no encoded surrogates (U+D800..U+DFFF).
                        val low = if (b1 == 0xE0) 0xA0 else 0x80
                        val high = if (b1 == 0xED) 0x9F else 0xBF
                        val b2 = continuation(bytes, i + 1, low, high)
                        val b3 = continuation(bytes, i + 2, 0x80, 0xBF)
                        scratch[pos++] = (((b1 and 0x0F) shl 12) or (b2 shl 6) or b3).toChar()
                        i += 3
                    }
                    b1 in 0xF0..0xF4 -> {
                        // F0: no overlong forms; F4: nothing above U+10FFFF.
                        val low = if (b1 == 0xF0) 0x90 else 0x80
                        val high = if (b1 == 0xF4) 0x8F else 0xBF
                        val b2 = continuation(bytes, i + 1, low, high)
                        val b3 = continuation(bytes, i + 2, 0x80, 0xBF)
                        val b4 = continuation(bytes, i + 3, 0x80, 0xBF)
                        val shifted = (((b1 and 0x07) shl 18) or (b2 shl 12) or (b3 shl 6) or b4) - 0x10000
                        scratch[pos++] = (0xD800 or (shifted shr 10)).toChar()
                        scratch[pos++] = (0xDC00 or (shifted and 0x3FF)).toChar()
                        i += 4
                    }
                    else -> throw IllegalArgumentException("Invalid UTF-8 lead byte at offset $i")
                }
            }
            return scratch.copyOf(pos)
        } finally {
            fillZero(scratch)
        }
    }

    /** The low 6 bits of the continuation byte at [index], which must lie in [low]..[high]. */
    private fun continuation(bytes: ByteArray, index: Int, low: Int, high: Int): Int {
        if (index >= bytes.size) throw IllegalArgumentException("Truncated UTF-8 sequence at offset $index")
        val b = bytes[index].toInt() and 0xFF
        if (b < low || b > high) throw IllegalArgumentException("Invalid UTF-8 continuation byte at offset $index")
        return b and 0x3F
    }

    private const val REPLACEMENT_CHAR = 0xFFFD

    private val HEX_CHARS = "0123456789abcdef".toCharArray()

    /**
     * Converts a ByteArray to a Hex CharArray without creating a transient String.
     */
    fun toHex(data: ByteArray): CharArray {
        val result = CharArray(data.size * 2)
        for (i in data.indices) {
            val v = data[i].toInt() and 0xFF
            result[i * 2] = HEX_CHARS[v ushr 4]
            result[i * 2 + 1] = HEX_CHARS[v and 0x0F]
        }
        return result
    }

    /**
     * Converts a Hex CharArray back to a ByteArray without creating a transient String.
     * Errors report the position only, never the offending (possibly secret) character.
     */
    fun fromHex(chars: CharArray): ByteArray {
        require(chars.size % 2 == 0) { "Hex string must have an even length" }
        val result = ByteArray(chars.size / 2)
        for (i in result.indices) {
            val h = parseHexDigit(chars[i * 2], i * 2)
            val l = parseHexDigit(chars[i * 2 + 1], i * 2 + 1)
            result[i] = ((h shl 4) or l).toByte()
        }
        return result
    }

    private fun parseHexDigit(c: Char, index: Int): Int = when (c) {
        in '0'..'9' -> c - '0'
        in 'a'..'f' -> c - 'a' + 10
        in 'A'..'F' -> c - 'A' + 10
        else -> throw IllegalArgumentException("Invalid hex digit at index $index")
    }

    private val B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray()
    private val B64_URL_SAFE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".toCharArray()
    private val B64_INV = inverse(B64_CHARS)
    private val B64_URL_SAFE_INV = inverse(B64_URL_SAFE_CHARS)

    private fun inverse(alphabet: CharArray) = IntArray(128) { -1 }.also { inv ->
        alphabet.forEachIndexed { i, c -> inv[c.code] = i }
    }

    /**
     * Converts a ByteArray to a Base64 CharArray without creating a transient String.
     */
    fun toBase64(data: ByteArray, urlSafe: Boolean = false, pad: Boolean = true): CharArray {
        val alphabet = if (urlSafe) B64_URL_SAFE_CHARS else B64_CHARS
        val resultSize = if (pad) (data.size + 2) / 3 * 4 else (data.size * 8 + 5) / 6
        val result = CharArray(resultSize)
        var i = 0
        var r = 0
        while (i < data.size) {
            val b0 = data[i++].toInt() and 0xFF
            val b1 = if (i < data.size) data[i++].toInt() and 0xFF else -1
            val b2 = if (i < data.size) data[i++].toInt() and 0xFF else -1

            result[r++] = alphabet[b0 ushr 2]
            if (b1 != -1) {
                result[r++] = alphabet[(b0 and 0x03 shl 4) or (b1 ushr 4)]
                if (b2 != -1) {
                    result[r++] = alphabet[(b1 and 0x0F shl 2) or (b2 ushr 6)]
                    result[r++] = alphabet[b2 and 0x3F]
                } else {
                    result[r++] = alphabet[b1 and 0x0F shl 2]
                    if (pad) result[r++] = '='
                }
            } else {
                result[r++] = alphabet[b0 and 0x03 shl 4]
                if (pad) {
                    result[r++] = '='
                    result[r++] = '='
                }
            }
        }
        return result
    }

    /**
     * Converts a Base64 CharArray to a ByteArray without creating a transient String.
     *
     * Strict and canonical: padding is optional but, when present, must be the correct trailing `=`/`==`; a length
     * of 4n+1 data characters, characters outside the alphabet (including non-ASCII) and non-zero trailing bits all
     * throw [IllegalArgumentException]. Whitespace is ignored. Errors report positions, never input characters.
     */
    fun fromBase64(chars: CharArray, urlSafe: Boolean = false): ByteArray {
        val inv = if (urlSafe) B64_URL_SAFE_INV else B64_INV

        var dataLen = 0
        var padLen = 0
        for ((index, c) in chars.withIndex()) {
            if (c.isWhitespace()) continue
            if (c == '=') {
                padLen++
                continue
            }
            if (padLen > 0) throw IllegalArgumentException("Base64 data after padding at index $index")
            if (c.code >= 128 || inv[c.code] < 0) throw IllegalArgumentException("Invalid Base64 character at index $index")
            dataLen++
        }
        val remainder = dataLen % 4
        if (remainder == 1) throw IllegalArgumentException("Invalid Base64 length")
        if (padLen > 0 && padLen != (4 - remainder) % 4) throw IllegalArgumentException("Invalid Base64 padding")

        val result = ByteArray(dataLen * 3 / 4)
        var r = 0
        var bits = 0
        var buffer = 0
        for (c in chars) {
            if (c.isWhitespace() || c == '=') continue
            buffer = ((buffer shl 6) or inv[c.code]) and 0xFFFFFF
            bits += 6
            if (bits >= 8) {
                bits -= 8
                result[r++] = (buffer ushr bits and 0xFF).toByte()
            }
        }
        // Canonical encodings leave the unused trailing bits zero; anything else is a malleated encoding.
        if (buffer and ((1 shl bits) - 1) != 0) {
            fillZero(result)
            throw IllegalArgumentException("Non-canonical Base64 encoding")
        }
        return result
    }

    /**
     * Safe comparison for CharArrays to prevent side-channel timing attacks.
     */
    fun contentEquals(a: CharArray?, b: CharArray?): Boolean {
        if (a === b) return true
        if (a == null || b == null) return false
        if (a.size != b.size) return false
        var result = 0
        for (i in a.indices) {
            result = result or (a[i].code xor b[i].code)
        }
        return result == 0
    }
}
