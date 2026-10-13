package com.sino.sdk.vault

import com.sino.sdk.crypto.SecurityUtils
import com.sino.sdk.crypto.VaultManifest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.AfterClass
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.security.MessageDigest

/**
 * Interop with a vault written by Sino's own core code (`src/test/resources/fixtures/core-vault`, see its README):
 * two providers' `SinoVault` folders, the recovery backup, the signed device list (two devices, one revoked), a
 * tombstone, a trashed file, a decoy vault namespace, a two-chunk file, compressed files and Unicode paths.
 */
class CoreVaultInteropTest {

    @get:Rule
    val temp = TemporaryFolder()

    companion object {
        private val fixture = File(CoreVaultInteropTest::class.java.getResource("/fixtures/core-vault")!!.toURI())
        private val expected: JsonObject = Json.parseToJsonElement(File(fixture, "expected.json").readText()).jsonObject
        private val providerA = File(fixture, "provider-a")
        private val providerB = File(fixture, "provider-b")

        private lateinit var phrase: String

        @BeforeClass
        @JvmStatic
        fun load() {
            phrase = File(fixture, "phrase.txt").readText()
        }

        @AfterClass
        @JvmStatic
        fun clear() {
            phrase = ""
        }

        fun words() = RecoveryKit.splitWords(phrase.toCharArray())
        fun files(key: String): Map<String, String> = expected[key]!!.jsonObject.mapValues { it.value.jsonPrimitive.content }
        fun sha256(file: File) = SecurityUtils.toHex(MessageDigest.getInstance("SHA-256").digest(file.readBytes())).concatToString()
    }

    private fun copyOf(dir: File): File = File(temp.newFolder(), dir.name).also { dir.copyRecursively(it) }

    private fun recovered(out: File): Map<String, String> =
        out.walkTopDown().filter { it.isFile }.associate { it.relativeTo(out).invariantSeparatorsPath to sha256(it) }

    @Test
    fun `recovers every live file of a core vault from two providers, byte for byte`() {
        val out = temp.newFolder("out")
        VaultRecovery.open(listOf(providerA, providerB), words()).use { vault ->
            val report = vault.recover(out)
            assertTrue(report.failed.joinToString(), report.failed.isEmpty())
            assertEquals(files("files"), recovered(out))
            // The trashed file is reported, not silently dropped.
            assertTrue(report.skipped.any { it.path == "DCIM/Camera/trashed.txt" })
        }
        // gone.txt (listed only by provider B's older batch, deleted in provider A's newer one) and the decoy
        // vault's file are not recovered.
        assertFalse(File(out, "gone.txt").exists())
        assertFalse(File(out, "decoy.txt").exists())
    }

    @Test
    fun `include trashed also recovers the trash`() {
        val out = temp.newFolder("out")
        VaultRecovery.open(listOf(providerA, providerB), words()).use { it.recover(out, includeTrashed = true) }
        assertEquals(files("files") + files("trashed"), recovered(out))
    }

    @Test
    fun `merges folders across providers - each provider alone misses files`() {
        VaultRecovery.open(listOf(providerA), words()).use { vault ->
            val paths = vault.index().files.map { it.path }.toSet()
            assertFalse("IMG_0002 was published only to provider B", "DCIM/Camera/IMG_0002.jpg" in paths)
        }
        VaultRecovery.open(listOf(providerB), words()).use { vault ->
            val index = vault.index()
            // Provider B alone still lists gone.txt: its own batch is older than the deletion.
            assertTrue("gone.txt" in index.files.map { it.path })
            assertTrue("The decoy namespace is never read", index.problems.none { "decoy" in it.message })
        }
    }

    @Test
    fun `a damaged copy is discarded and the other provider's copy is used`() {
        val a = copyOf(providerA)
        val b = copyOf(providerB)
        val out = temp.newFolder("out")
        VaultRecovery.open(listOf(a, b), words()).use { vault ->
            val notes = vault.index().files.single { it.path == "notes.txt" }
            assertEquals(2, notes.copies.size)
            val copyA = notes.copies.single { it.startsWith(a) }
            copyA.writeBytes(copyA.readBytes().also { it[40] = (it[40] + 1).toByte() })

            val report = vault.recover(out)
            assertTrue(report.failed.joinToString(), report.failed.isEmpty())
            assertEquals(files("files")["notes.txt"], sha256(File(out, "notes.txt")))
        }
    }

    @Test
    fun `a file whose only copy is damaged fails, leaves nothing behind, and the rest still recovers`() {
        val a = copyOf(providerA)
        val out = temp.newFolder("out")
        VaultRecovery.open(listOf(a, providerB), words()).use { vault ->
            val report = vault.index().files.single { it.path == "archive.bin" }.copies.single()
            report.writeBytes(report.readBytes().also { it[it.size - 1] = (it[it.size - 1] + 1).toByte() })

            val result = vault.recover(out)
            assertEquals(listOf("archive.bin"), result.failed.map { it.path })
            assertTrue(result.failed.single().message, "authentication failed" in result.failed.single().message)
            assertFalse(File(out, "archive.bin").exists())
            assertTrue(out.listFiles()!!.none { it.name.contains("sino-") })
            assertEquals(files("files").size - 1, result.recovered.size)
        }
    }

    @Test
    fun `existing files are never overwritten`() {
        val out = temp.newFolder("out")
        File(out, "notes.txt").writeText("mine")
        VaultRecovery.open(listOf(providerA, providerB), words()).use { vault ->
            val report = vault.recover(out)
            assertTrue(report.skipped.any { it.path == "notes.txt" })
        }
        assertEquals("mine", File(out, "notes.txt").readText())
    }

    @Test
    fun `the device list core signed verifies, with its devices and revocation`() {
        VaultRecovery.open(listOf(providerA), words()).use { vault ->
            val report = vault.verifyManifest()
            val manifest = report.manifest!!
            assertTrue(report.rejected.isEmpty())
            assertEquals(expected["vaultIdentifier"]!!.jsonPrimitive.content, manifest.vaultIdentifier)
            assertEquals(expected["devices"]!!.jsonPrimitive.content.toInt(), manifest.keyEnvelopes.size)
            assertTrue(manifest.keyEnvelopes.any { it.keyId == expected["phone"]!!.jsonPrimitive.content })
            assertEquals(listOf(expected["revoked"]!!.jsonPrimitive.content), manifest.revokedKeyIds)
        }
    }

    @Test
    fun `a tampered or foreign device list is rejected`() {
        val a = copyOf(providerA)
        val file = File(a, "SinoVault/security/vault_manifest.json")
        val original = VaultManifest.fromJson(file.readText())
        // Un-revoking the device without the vault's signing key.
        file.writeText(original.copy(revokedKeyIds = emptyList()).toJson())
        VaultRecovery.open(listOf(a), words()).use { vault ->
            val report = vault.verifyManifest()
            assertNull(report.manifest)
            assertEquals(1, report.rejected.size)
        }
        // A validly signed list of another vault (here: the same list, relabelled) is rejected too.
        file.writeText(original.copy(vaultIdentifier = "0".repeat(32)).toJson())
        VaultRecovery.open(listOf(a), words()).use { assertNull(it.verifyManifest().manifest) }
    }

    @Test
    fun `a wrong phrase is refused`() {
        val wrong = words().toMutableList().also { it[23] = "zoo".toCharArray() }
        assertThrows(IllegalArgumentException::class.java) { VaultRecovery.open(listOf(providerA), wrong) }
        assertThrows(IllegalArgumentException::class.java) { VaultRecovery.open(listOf(providerA), words().drop(1)) }
    }

    @Test
    fun `a batch moved to another folder's location is ignored`() {
        val a = copyOf(providerA)
        // The real vault's metadata namespace is the one with folder directories (camera, docs and a deleted folder).
        val realNs = File(a, "SinoVault/metadata").listFiles()!!.single { ns -> ns.listFiles()!!.any { it.isDirectory } }
        val batches = realNs.listFiles()!!.filter { it.isDirectory }.map { it.listFiles()!!.single() }
        assertEquals(3, batches.size)
        batches.drop(1).forEach { batches.first().copyTo(it, overwrite = true) }

        VaultRecovery.open(listOf(a), words()).use { vault ->
            val index = vault.index()
            assertTrue(index.problems.joinToString(), index.problems.any { "not where its folder belongs" in it.message })
            // Provider A lists 3 root files, 2 camera files and 1 document; only the folder whose batch was copied
            // stays, and its files are not listed a second time.
            val paths = index.files.map { it.path }
            assertEquals(paths.distinct(), paths)
            assertTrue(paths.toString(), paths.size in 3..5)
        }
    }

    @Test
    fun `missing recovery files are reported`() {
        val empty = temp.newFolder("empty")
        assertThrows(IllegalStateException::class.java) { VaultRecovery.open(listOf(empty), words()) }
    }
}
