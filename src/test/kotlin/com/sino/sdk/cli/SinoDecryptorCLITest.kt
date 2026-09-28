package com.sino.sdk.cli

import com.sino.sdk.crypto.AESEncryptionEngine
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.ByteArrayInputStream
import java.io.FileOutputStream
import java.security.SecureRandom
import java.util.Base64

class SinoDecryptorCLITest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private val engine = AESEncryptionEngine()
    private val random = SecureRandom()

    @Test
    fun `SinoDecryptorCLI main should successfully decrypt file from command line arguments`() {
        val originalText = "Sino Standalone Recovery Test Payload 2026"
        val dek = ByteArray(32).also { random.nextBytes(it) }
        val iv = ByteArray(12).also { random.nextBytes(it) }

        val encryptedFile = tempFolder.newFile("test.enc")
        val decryptedFile = tempFolder.newFile("test.dec")

        // Encrypt test payload
        FileOutputStream(encryptedFile).use { out ->
            engine.encrypt(ByteArrayInputStream(originalText.toByteArray()), out, dek, iv)
        }

        val base64Dek = Base64.getEncoder().encodeToString(dek)
        val base64Iv = Base64.getEncoder().encodeToString(iv)

        // Run CLI main function
        SinoDecryptorCLI.main(
            arrayOf(
                encryptedFile.absolutePath,
                decryptedFile.absolutePath,
                base64Dek,
                base64Iv
            )
        )

        assertTrue(decryptedFile.exists())
        val decryptedContent = decryptedFile.readText()
        assertArrayEquals(originalText.toByteArray(), decryptedContent.toByteArray())
    }

    @Test
    fun `SinoDecryptorCLI main should successfully decrypt file using key file mode`() {
        val originalText = "Sino Key File Recovery Test Payload 2026"
        val dek = ByteArray(32).also { random.nextBytes(it) }
        val iv = ByteArray(12).also { random.nextBytes(it) }

        val encryptedFile = tempFolder.newFile("test_file.enc")
        val decryptedFile = tempFolder.newFile("test_file.dec")
        val keyFile = tempFolder.newFile("keys.txt")

        FileOutputStream(encryptedFile).use { out ->
            engine.encrypt(ByteArrayInputStream(originalText.toByteArray()), out, dek, iv)
        }

        val base64Dek = Base64.getEncoder().encodeToString(dek)
        val base64Iv = Base64.getEncoder().encodeToString(iv)

        keyFile.writeText("DEK=$base64Dek\nIV=$base64Iv\n")

        SinoDecryptorCLI.main(
            arrayOf(
                encryptedFile.absolutePath,
                decryptedFile.absolutePath,
                "--key-file",
                keyFile.absolutePath
            )
        )

        assertTrue(decryptedFile.exists())
        val decryptedContent = decryptedFile.readText()
        assertArrayEquals(originalText.toByteArray(), decryptedContent.toByteArray())
    }

    @Test
    fun `SinoDecryptorCLI main should successfully decrypt file using stdin mode`() {
        val originalText = "Sino Stdin Recovery Test Payload 2026"
        val dek = ByteArray(32).also { random.nextBytes(it) }
        val iv = ByteArray(12).also { random.nextBytes(it) }

        val encryptedFile = tempFolder.newFile("test_stdin.enc")
        val decryptedFile = tempFolder.newFile("test_stdin.dec")

        FileOutputStream(encryptedFile).use { out ->
            engine.encrypt(ByteArrayInputStream(originalText.toByteArray()), out, dek, iv)
        }

        val base64Dek = Base64.getEncoder().encodeToString(dek)
        val base64Iv = Base64.getEncoder().encodeToString(iv)

        val stdinBytes = "$base64Dek\n$base64Iv\n".toByteArray()
        val originalStdin = System.`in`
        try {
            System.setIn(ByteArrayInputStream(stdinBytes))
            SinoDecryptorCLI.main(
                arrayOf(
                    encryptedFile.absolutePath,
                    decryptedFile.absolutePath,
                    "--key-stdin"
                )
            )
        } finally {
            System.setIn(originalStdin)
        }

        assertTrue(decryptedFile.exists())
        val decryptedContent = decryptedFile.readText()
        assertArrayEquals(originalText.toByteArray(), decryptedContent.toByteArray())
    }
}
