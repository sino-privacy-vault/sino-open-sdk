package com.sino.sdk.cli

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.PrintStream

class SinoDecryptorCLITest {

    @get:Rule
    val temp = TemporaryFolder()

    private val fixture = File(javaClass.getResource("/fixtures/core-vault")!!.toURI())
    private val a = File(fixture, "provider-a").path
    private val b = File(fixture, "provider-b").path
    private val phraseFile = File(fixture, "phrase.txt")

    private fun run(vararg args: String, stdin: ByteArray = ByteArray(0)): Pair<Int, String> {
        val bytes = ByteArrayOutputStream()
        val code = SinoDecryptorCLI.run(arrayOf(*args), PrintStream(bytes, true, "UTF-8"), ByteArrayInputStream(stdin))
        return code to bytes.toString("UTF-8")
    }

    @Test
    fun `recover writes every file and reports the trash`() {
        val out = temp.newFolder("out")
        val (code, text) = run("recover", "--vault", a, "--vault", b, "--out", out.path, "--phrase-file", phraseFile.path)
        assertEquals(text, SinoDecryptorCLI.EXIT_OK, code)
        assertTrue(text, "Recovered 6 file(s)" in text)
        assertTrue(text, "SKIPPED DCIM/Camera/trashed.txt" in text)
        assertTrue(File(out, "DCIM/Camera/IMG_0002.jpg").isFile)
    }

    @Test
    fun `the phrase can come from stdin, and never appears in the output`() {
        val phrase = phraseFile.readBytes()
        val (code, text) = run("list", "--vault", a, "--vault", b, "--phrase-stdin", stdin = phrase)
        assertEquals(text, SinoDecryptorCLI.EXIT_OK, code)
        assertTrue(text, "DCIM/Camera/IMG_0001.jpg" in text)
        assertTrue(text, "7 file(s)." in text) // 6 live files and the trashed one
        phraseFile.readText().split(Regex("\\s+")).filter { it.length > 3 }.forEach { word ->
            assertFalse("The output must not contain the phrase", text.contains(" ${word.lowercase()} "))
        }
    }

    @Test
    fun `verify-manifest lists the devices and the revocation`() {
        val (code, text) = run("verify-manifest", "--vault", a, "--phrase-file", phraseFile.path)
        assertEquals(text, SinoDecryptorCLI.EXIT_OK, code)
        assertTrue(text, "Device list verified (ML-DSA-65)" in text)
        assertTrue(text, "revoked device-" in text)
        assertEquals(text, 2, Regex("\\n  device ").findAll(text).count())
    }

    @Test
    fun `usage errors exit with code 2 and never ask for the phrase on the command line`() {
        assertEquals(SinoDecryptorCLI.EXIT_ERROR, run().first)
        assertEquals(SinoDecryptorCLI.EXIT_ERROR, run("decrypt", "--vault", a).first)
        assertEquals(SinoDecryptorCLI.EXIT_ERROR, run("list", "--vault", a, "legal", "winner").first)
        assertEquals(SinoDecryptorCLI.EXIT_ERROR, run("recover", "--vault", a, "--phrase-file", phraseFile.path).first)
        assertEquals(SinoDecryptorCLI.EXIT_ERROR, run("list", "--vault", File(fixture, "missing").path, "--phrase-file", phraseFile.path).first)
        assertEquals(SinoDecryptorCLI.EXIT_ERROR, run("list", "--vault", a, "--phrase-file", phraseFile.path, "--phrase-stdin").first)
        assertEquals(SinoDecryptorCLI.EXIT_OK, run("--help").first)
    }

    @Test
    fun `a wrong or short phrase exits with code 2`() {
        val wrong = phraseFile.readText().trim().split(Regex("\\s+")).toMutableList().also { it[5] = "zoo" }.joinToString(" ")
        val (code, text) = run("list", "--vault", a, "--phrase-stdin", stdin = wrong.toByteArray())
        assertEquals(SinoDecryptorCLI.EXIT_ERROR, code)
        assertTrue(text, "does not match" in text)
        val (short, shortText) = run("list", "--vault", a, "--phrase-stdin", stdin = "only three words".toByteArray())
        assertEquals(SinoDecryptorCLI.EXIT_ERROR, short)
        assertTrue(shortText, "24 words (got 3)" in shortText)
    }

    @Test
    fun `failures make the exit code 1`() {
        val damaged = File(temp.newFolder(), "provider-a").also { File(a).copyRecursively(it) }
        damaged.walkTopDown().filter { it.name.endsWith(".enc") }.forEach { it.writeBytes(it.readBytes().also { b -> b[0] = (b[0] + 1).toByte() }) }
        val (code, text) = run("recover", "--vault", damaged.path, "--out", temp.newFolder("out").path, "--phrase-file", phraseFile.path)
        assertEquals(text, SinoDecryptorCLI.EXIT_PARTIAL, code)
        assertTrue(text, "FAILED" in text)
    }
}
