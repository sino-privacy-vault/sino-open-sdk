package com.sino.sdk.util

import org.junit.Assert.assertEquals
import org.junit.Test

class SinoPrivacyEngineTest {

    private val engine = SinoPrivacyEngine()

    @Test
    fun `sanitize redacts emails`() {
        val input = "Error for user@domain.com"
        val expected = "Error for [REDACTED_EMAIL]"
        assertEquals(expected, engine.sanitize(input))
    }

    @Test
    fun `sanitize redacts BIP39 phrases`() {
        // The rule is case-insensitive, so the label is separated by a colon (a plain word would join the phrase).
        val input = "Seed: apple banana cherry dog elephant fish grape horse ice jacket kangaroo lemon"
        val expected = "Seed: [REDACTED_BIP39]"
        assertEquals(expected, engine.sanitize(input))
    }

    @Test
    fun `sanitize redacts multiple sensitive items in single pass`() {
        val input = "User dev@sino.com used token ya29.auth123 to decrypt photo.jpg"
        val expected = "User [REDACTED_EMAIL] used token [REDACTED_AUTH_TOKEN] to decrypt [REDACTED_FILE_NAME]"
        assertEquals(expected, engine.sanitize(input))
    }

    @Test
    fun `sanitize handles Base64 blobs`() {
        // SGVsbG8gV29ybGQgZnJvbSBTaW5vIFNlY3VyZSBVbml2ZXJzZSAyMDI2IQ== is 56 chars
        // The regex threshold is {15,} blocks of 4 = 60 chars.
        val longBase64 = "SGVsbG8gV29ybGQgZnJvbSBTaW5vIFNlY3VyZSBVbml2ZXJzZSAyMDI2ISBXZSBhcmUgaGFyZGVuaW5nIHRoZSBlbmdpbmUgdG8gUHJvdG9jb2wgdjMuMi4="
        val input = "Payload: $longBase64"
        val expected = "Payload: [REDACTED_BASE64]"
        assertEquals(expected, engine.sanitize(input))
    }

    // --- Parity with Sino's core sanitizer (PV1-PV3) --------------------------------------------------------

    @Test
    fun `a 32-byte key in base64 is redacted`() {
        val key = java.util.Base64.getEncoder().encodeToString(ByteArray(32) { (it * 7 + 3).toByte() })
        assertEquals("dek [REDACTED_BASE64]", engine.sanitize("dek $key"))
    }

    @Test
    fun `credentials are redacted with their value`() {
        assertEquals("login [REDACTED_CREDENTIAL] ok", engine.sanitize("login password=hunter2 ok"))
        assertEquals("{\"[REDACTED_CREDENTIAL]\"}", engine.sanitize("{\"secretAccessKey\":\"abcd/efgh\"}"))
    }

    @Test
    fun `capitalised, comma-separated and numbered phrases are redacted`() {
        val words = "Abandon Ability Able About Above Absent Absorb Abstract Absurd Abuse Access Accident".split(" ")
        assertEquals("p: [REDACTED_BIP39]", engine.sanitize("p: " + words.joinToString(", ")))
        assertEquals("p: [REDACTED_BIP39]", engine.sanitize("p: " + words.mapIndexed { i, w -> "${i + 1}. $w" }.joinToString(" ")))
    }

    @Test
    fun `sanitizeForLog never throws`() {
        assertEquals("[REDACTED_EMAIL]", engine.sanitizeForLog("a@b.co"))
    }
}
