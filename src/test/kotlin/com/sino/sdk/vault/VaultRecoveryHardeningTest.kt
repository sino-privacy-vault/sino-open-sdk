package com.sino.sdk.vault

import com.sino.sdk.crypto.AESEncryptionEngine
import com.sino.sdk.crypto.SecurityUtils
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.security.MessageDigest
import java.security.SecureRandom

/** Hostile and malformed vault contents, built with the SDK's own writers (the format is checked by the interop test). */
class VaultRecoveryHardeningTest {

    @get:Rule
    val temp = TemporaryFolder()

    private val random = SecureRandom()
    private val aes = AESEncryptionEngine()
    private val phrase = List(24) { "word$it" }

    /** A one-provider vault in [dir]/SinoVault. */
    private inner class TestVault(val dir: File) {
        val rmk = ByteArray(32).also { random.nextBytes(it) }
        val salt = ByteArray(32).also { random.nextBytes(it) }
        val keys = VaultKeys(rmk)
        val root = File(dir, "SinoVault")

        init {
            val kit = RecoveryKit()
            val recoverySalt = RecoveryKit.recoverySalt(salt)
            val kek = kit.deriveKek(phrase.map { it.toCharArray() }, recoverySalt)
            File(root, "security").mkdirs()
            File(root, "security/vault_salt.public").writeBytes(recoverySalt)
            File(root, "security/rmk_backup.bin").writeBytes(kit.sealBackup(rmk, salt, kek))
        }

        fun entry(name: String, plain: ByteArray, folder: String = "", tweak: (MediaMetadata) -> MediaMetadata = { it }): MediaMetadata {
            val dek = aes.generateDEK()
            val iv = aes.generateIV()
            val out = ByteArrayOutputStream()
            aes.encryptChunked(ByteArrayInputStream(plain), out, dek, iv)
            val cloudName = SecurityUtils.toHex(ByteArray(16).also { random.nextBytes(it) }).concatToString()
            val entry = tweak(MediaMetadata(
                originalName = name, relativePath = folder, mimeType = "text/plain", size = plain.size.toLong(), checksum = sha(plain),
                encryptedDEK = keys.wrapDek(dek), iv = SecurityUtils.toBase64(iv).concatToString(), timestamp = 1, isChunked = true,
                cloudChecksum = sha(plain), cloudName = cloudName,
            ))
            val blobDir = listOf(root.path, "blobs", VaultCloudLayout.namespace(salt, "blobs"), VaultCloudLayout.folderDirName(salt, folder)).filter { it.isNotEmpty() }
            File(blobDir.joinToString(File.separator), "$cloudName.enc").apply { parentFile.mkdirs(); writeBytes(out.toByteArray()) }
            return entry
        }

        fun publish(folder: String, files: Map<String, MediaMetadata>, version: Long = 1) {
            val dir = listOf(root.path, "metadata", VaultCloudLayout.namespace(salt, "metadata"), VaultCloudLayout.folderDirName(salt, folder)).filter { it.isNotEmpty() }
            File(dir.joinToString(File.separator), VaultCloudLayout.batchFileName(salt, folder)).apply {
                parentFile.mkdirs()
                writeBytes(FolderMetadataBatchCodec.encode(FolderMetadataBatch(folder, files, version), keys.metadataBatchKey()))
            }
        }

        fun open() = VaultRecovery.open(listOf(dir), phrase.map { it.toCharArray() })
    }

    private fun sha(bytes: ByteArray) = SecurityUtils.toHex(MessageDigest.getInstance("SHA-256").digest(bytes)).concatToString()

    @Test
    fun `names that could escape the output folder are never written`() {
        val vault = TestVault(temp.newFolder("cloud"))
        val ok = vault.entry("ok.txt", "fine".encodeToByteArray())
        vault.publish("", mapOf(
            "ok.txt" to ok,
            "../escape.txt" to vault.entry("../escape.txt", "x".encodeToByteArray()),
            "..\\escape2.txt" to vault.entry("..\\escape2.txt", "x".encodeToByteArray()),
            "C:evil.txt" to vault.entry("C:evil.txt", "x".encodeToByteArray()),
        ))
        vault.publish("a/../../up", mapOf("f.txt" to vault.entry("f.txt", "x".encodeToByteArray(), folder = "a/../../up")))

        val parent = temp.newFolder("parent")
        val out = File(parent, "out")
        val report = vault.open().use { it.recover(out) }

        assertEquals(listOf("ok.txt"), report.recovered)
        assertEquals(4, report.failed.count { "unsafe file path" in it.message })
        assertEquals(listOf("out"), parent.list()!!.toList())
        assertEquals(listOf("ok.txt"), out.list()!!.toList())
    }

    @Test
    fun `entries of the other vault, without a valid cloud name, or in an unsupported format are not recovered`() {
        val vault = TestVault(temp.newFolder("cloud"))
        vault.publish("", mapOf(
            "decoy.txt" to vault.entry("decoy.txt", "d".encodeToByteArray()) { it.copy(isDuress = true) },
            "noname.txt" to vault.entry("noname.txt", "n".encodeToByteArray()) { it.copy(cloudName = null) },
            "traversal.txt" to vault.entry("traversal.txt", "t".encodeToByteArray()) { it.copy(cloudName = "../../x") },
            "whole.txt" to vault.entry("whole.txt", "w".encodeToByteArray()) { it.copy(isChunked = false) },
            "v1.txt" to vault.entry("v1.txt", "v".encodeToByteArray()) { it.copy(encryptionVersion = 1) },
        ))
        val report = vault.open().use { it.recover(temp.newFolder("out")) }

        assertTrue(report.recovered.isEmpty())
        assertTrue(report.skipped.any { it.path == "decoy.txt" && "other vault" in it.message })
        assertTrue(report.skipped.any { it.path == "noname.txt" })
        assertTrue(report.skipped.any { it.path == "traversal.txt" })
        assertEquals(setOf("whole.txt", "v1.txt"), report.failed.filter { "unsupported encryption format" in it.message }.map { it.path }.toSet())
    }

    @Test
    fun `a wrong recorded checksum, a missing blob and a foreign DEK fail without output`() {
        val vault = TestVault(temp.newFolder("cloud"))
        val other = VaultKeys(ByteArray(32).also { random.nextBytes(it) })
        val missing = vault.entry("missing.txt", "m".encodeToByteArray())
        vault.publish("", mapOf(
            "good.txt" to vault.entry("good.txt", "good".encodeToByteArray()),
            "bad-sum.txt" to vault.entry("bad-sum.txt", "s".encodeToByteArray()) { it.copy(cloudChecksum = "00".repeat(32)) },
            "missing.txt" to missing.copy(cloudName = "f".repeat(32)),
            "foreign.txt" to vault.entry("foreign.txt", "f".encodeToByteArray()) { it.copy(encryptedDEK = other.wrapDek(ByteArray(32))) },
        ))
        val out = temp.newFolder("out")
        val report = vault.open().use { it.recover(out) }

        assertEquals(listOf("good.txt"), report.recovered)
        assertTrue(report.failed.single { it.path == "bad-sum.txt" }.message.contains("checksum"))
        assertTrue(report.failed.single { it.path == "missing.txt" }.message.contains("no provider copy"))
        assertTrue(report.failed.any { it.path == "foreign.txt" })
        assertEquals(listOf("good.txt"), out.list()!!.toList())
    }

    @Test
    fun `an unreadable batch is reported and the other folders still recover`() {
        val vault = TestVault(temp.newFolder("cloud"))
        vault.publish("", mapOf("a.txt" to vault.entry("a.txt", "a".encodeToByteArray())))
        vault.publish("Photos", mapOf("p.txt" to vault.entry("p.txt", "p".encodeToByteArray(), folder = "Photos")))
        val photosBatch = File(vault.root, "metadata/${VaultCloudLayout.namespace(vault.salt, "metadata")}/${VaultCloudLayout.folderDirName(vault.salt, "Photos")}")
            .listFiles()!!.single()
        photosBatch.writeBytes(photosBatch.readBytes().also { it[20] = (it[20] + 1).toByte() })

        val report = vault.open().use { it.recover(temp.newFolder("out")) }
        assertEquals(listOf("a.txt"), report.recovered)
        assertTrue(report.skipped.joinToString(), report.skipped.any { "unreadable metadata batch" in it.message })
        assertFalse("Problems never include file contents or keys", report.skipped.any { "Exception:" in it.message })
    }

    @Test
    fun `compressed files are decompressed after the checksum of the encrypted bytes is verified`() {
        val vault = TestVault(temp.newFolder("cloud"))
        val plain = "compressible ".repeat(1000).encodeToByteArray()
        val gz = ByteArrayOutputStream().also { java.util.zip.GZIPOutputStream(it).use { z -> z.write(plain) } }.toByteArray()
        val entry = vault.entry("c.txt", gz) { it.copy(isCompressed = true, checksum = sha(plain)) }
        vault.publish("", mapOf("c.txt" to entry))
        val out = temp.newFolder("out")
        vault.open().use { it.recover(out) }
        assertEquals(sha(plain), sha(File(out, "c.txt").readBytes()))
    }
}
