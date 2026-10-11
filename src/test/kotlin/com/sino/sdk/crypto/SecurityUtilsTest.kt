package com.sino.sdk.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64
import kotlin.random.Random
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse

class SecurityUtilsTest {

    @Test
    fun `fillZero physically wipes byte array`() {
        val data = byteArrayOf(1, 2, 3, 4, 5)
        SecurityUtils.fillZero(data)
        assertTrue(data.all { it == 0.toByte() })
    }

    @Test
    fun `fillZero physically wipes char array`() {
        val data = charArrayOf('a', 'b', 'c')
        SecurityUtils.fillZero(data)
        assertTrue(data.all { it == '\u0000' })
    }

    @Test
    fun `toUtf8 and fromUtf8 are reversible for complex strings`() {
        val original = "Elite Privacy: \u00a9 2026 \u20ac".toCharArray() // Copyright and Euro symbols
        val bytes = SecurityUtils.toUtf8(original)
        val recovered = SecurityUtils.fromUtf8(bytes)
        
        assertArrayEquals("UTF-8 round-trip failed for complex characters", original, recovered)
    }

    @Test
    fun `toUtf8 handles empty arrays`() {
        val original = charArrayOf()
        val bytes = SecurityUtils.toUtf8(original)
        assertTrue(bytes.isEmpty())
    }

    @Test
    fun `fromUtf8 handles empty arrays`() {
        val bytes = byteArrayOf()
        val recovered = SecurityUtils.fromUtf8(bytes)
        assertTrue(recovered.isEmpty())
    }

    @Test
    fun `toUtf8 and fromUtf8 handle supplementary characters`() {
        // "Sino 🔒" - contains the locked padlock emoji (4-byte UTF-8, U+1F512)
        val original = "Sino \ud83d\udd12".toCharArray()
        val bytes = SecurityUtils.toUtf8(original)
        
        // U+1F512 in UTF-8 is F0 9F 94 92
        org.junit.Assert.assertEquals(9, bytes.size)
        org.junit.Assert.assertEquals(0xF0.toByte(), bytes[5])
        
        val recovered = SecurityUtils.fromUtf8(bytes)
        assertArrayEquals("Emoji round-trip failed", original, recovered)
    }

    @Test
    fun `toHex and fromHex are reversible`() {
        val original = byteArrayOf(0x00, 0x01, 0x7F, 0x80.toByte(), 0xFF.toByte())
        val hex = SecurityUtils.toHex(original)
        
        org.junit.Assert.assertEquals("00017f80ff", String(hex))
        
        val recovered = SecurityUtils.fromHex(hex)
        assertArrayEquals(original, recovered)
    }

    @Test
    fun `toBase64 and fromBase64 are reversible`() {
        val original = "Sino Open SDK Forensic Verification".toByteArray()
        
        // 1. Standard
        val b64 = SecurityUtils.toBase64(original, urlSafe = false)
        val recovered = SecurityUtils.fromBase64(b64, urlSafe = false)
        assertArrayEquals("Standard Base64 failed", original, recovered)
        
        // 2. URL Safe
        val b64Url = SecurityUtils.toBase64(original, urlSafe = true)
        val recoveredUrl = SecurityUtils.fromBase64(b64Url, urlSafe = true)
        assertArrayEquals("URL Safe Base64 failed", original, recoveredUrl)
    }

    @Test
    fun `contentEquals is timing-attack resistant but accurate`() {
        val a = "token_123".toCharArray()
        val b = "token_123".toCharArray()
        val c = "token_456".toCharArray()

        assertTrue(SecurityUtils.contentEquals(a, b))
        assertTrue(SecurityUtils.contentEquals(null, null))
        assertTrue(!SecurityUtils.contentEquals(a, c))
        assertTrue(!SecurityUtils.contentEquals(a, null))
    }

    // --- Parity with Sino's core decoders (strict UTF-8 and base64, no input characters in errors) ----------

    private fun bytes(vararg values: Int) = ByteArray(values.size) { values[it].toByte() }

    @Test
    fun `fromUtf8 rejects malformed input with IllegalArgumentException, never an index error`() {
        listOf(
            bytes(0xC3),                    // truncated 2-byte
            bytes(0xE2, 0x82),              // truncated 3-byte
            bytes(0xF0, 0x9F, 0x98),        // truncated 4-byte
            bytes(0x80),                    // stray continuation
            bytes(0xC0, 0x80),              // overlong NUL
            bytes(0xE0, 0x80, 0x80),        // overlong 3-byte
            bytes(0xED, 0xA0, 0x80),        // encoded surrogate
            bytes(0xF4, 0x90, 0x80, 0x80),  // above U+10FFFF
            bytes(0xF5, 0x80, 0x80, 0x80),  // invalid lead
            bytes(0xC3, 0x28),              // bad continuation
        ).forEach { input ->
            assertFailsWith<IllegalArgumentException> { SecurityUtils.fromUtf8(input) }
        }
    }

    @Test
    fun `UTF-8 codec matches the platform codec on valid text, and lone surrogates become U+FFFD`() {
        val random = Random(42)
        val samples = listOf("", "abc", "größe", "日本語", "😀 emoji", "mixed é 漢 🎉 end") +
            List(200) { String(CharArray(random.nextInt(0, 24)) { random.nextInt(0x20, 0xD7FF).toChar() }) }
        samples.forEach { text ->
            val encoded = SecurityUtils.toUtf8(text.toCharArray())
            assertContentEquals(text.encodeToByteArray(), encoded, "Encoding of '$text'")
            assertEquals(text, SecurityUtils.fromUtf8(encoded).concatToString())
        }
        assertContentEquals(bytes(0x61, 0xEF, 0xBF, 0xBD, 0x62), SecurityUtils.toUtf8(charArrayOf('a', '\uD800', 'b')))
        assertContentEquals(bytes(0xEF, 0xBF, 0xBD), SecurityUtils.toUtf8(charArrayOf('\uDC00')))
    }

    @Test
    fun `fromBase64 is strict, canonical and agrees with java util Base64`() {
        val random = Random(7)
        repeat(200) {
            val data = random.nextBytes(random.nextInt(0, 70))
            val padded = Base64.getEncoder().encodeToString(data)
            assertContentEquals(data, SecurityUtils.fromBase64(padded.toCharArray()))
            assertContentEquals(data, SecurityUtils.fromBase64(padded.trimEnd('=').toCharArray()), "Unpadded input")
            assertContentEquals(data, SecurityUtils.fromBase64(Base64.getUrlEncoder().encodeToString(data).toCharArray(), urlSafe = true))
        }
        assertContentEquals("A".encodeToByteArray(), SecurityUtils.fromBase64(" Q Q = = ".toCharArray()), "Whitespace is ignored")

        // Includes "QR==", a non-canonical encoding of "A" (non-zero trailing bits).
        listOf("A", "QQ=", "QQ===", "QQ=A", "Q=Q=", "QR==", "QUJ=", "Zm9vYg-_", "é123").forEach { bad ->
            assertFailsWith<IllegalArgumentException>("'$bad'") { SecurityUtils.fromBase64(bad.toCharArray()) }
        }
    }

    @Test
    fun `decoder errors never echo input characters`() {
        val hex = runCatching { SecurityUtils.fromHex("0aQ7".toCharArray()) }.exceptionOrNull()!!
        assertFalse("Q" in hex.message!!, hex.message)
        val b64 = runCatching { SecurityUtils.fromBase64("abcé".toCharArray()) }.exceptionOrNull()!!
        assertFalse("é" in b64.message!!, b64.message)
        val b64b = runCatching { SecurityUtils.fromBase64("ab*d".toCharArray()) }.exceptionOrNull()!!
        assertFalse("*" in b64b.message!!, b64b.message)
    }
}
