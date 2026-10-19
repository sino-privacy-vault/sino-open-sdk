package com.sino.sdk.share

import com.sino.sdk.crypto.SecurityUtils
import com.sino.sdk.org.OrganisationRecovery
import com.sino.sdk.vault.RecoveryKit
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.security.MessageDigest

/**
 * A shared folder read without Sino (SPECIFICATION.md §13), against the folder Sino's own core wrote
 * (`fixtures/core-vault/share`): the fixture vault owns it with a colleague, both changed one file at once, and it has
 * subfolders, one of them in the trash.
 */
class SharedFolderInteropTest {

    @get:Rule
    val temp = TemporaryFolder()

    private val fixture = File(javaClass.getResource("/fixtures/core-vault")!!.toURI())
    private val org = File(fixture, "org")
    private val expected = Json.parseToJsonElement(File(fixture, "expected.json").readText()).jsonObject["share"]!!.jsonObject
    private val folder = File(fixture, "share/" + expected["shareId"]!!.jsonPrimitive.content)
    private val identity = File(fixture, "provider-a/SinoVault/security/share_identity.bin").readBytes()

    private fun map(name: String) = (expected[name] as JsonObject).mapValues { it.value.jsonPrimitive.content }

    private fun sha256(file: File) = SecurityUtils.toHex(MessageDigest.getInstance("SHA-256").digest(file.readBytes())).concatToString()

    /** Every file under [dir], by its path from [dir] ("/"-separated), to its SHA-256. */
    private fun tree(dir: File) = dir.walkTopDown().filter { it.isFile }.associate { it.relativeTo(dir).invariantSeparatorsPath to sha256(it) }

    private fun kits() = OrganisationRecovery.open(listOf(
        OrganisationRecovery.readKit(File(org, "kit-1.sinokit").readText()),
        OrganisationRecovery.readKit(File(org, "kit-3-paper.txt").readText()),
    ))

    private fun checkFolder(manifest: SharedFolderRecovery.Manifest, keys: SharedFolderRecovery.ShareKeys) {
        val index = SharedFolderRecovery.index(folder, manifest, keys)
        assertEquals(expected["name"]!!.jsonPrimitive.content, index.name)
        assertEquals(0, index.refusedBatches)
        assertEquals(map("files").keys, index.files.map { it.path }.toSet())
        assertEquals(map("trash").keys, index.trash.map { it.path }.toSet())
        assertEquals(2, index.files.count { it.conflict })
        assertEquals(listOf("Archive", "Specs", "Specs/2026"), index.folders)
        val out = temp.newFolder()
        SharedFolderRecovery.recover(folder, index, keys, out, includeTrashed = true)
        assertEquals(map("files") + map("trash"), tree(out))
    }

    @Test
    fun `the organisation's kits open the folder and every version of every file`() {
        val manifest = SharedFolderRecovery.readManifest(folder)
        kits().use { orgKeys -> SharedFolderRecovery.openWithKits(manifest, orgKeys).use { checkFolder(manifest, it) } }
    }

    @Test
    fun `a member reads it with its vault's root key, from the recovery phrase`() {
        val manifest = SharedFolderRecovery.readManifest(folder)
        val security = File(fixture, "provider-a/SinoVault/security")
        val kit = RecoveryKit()
        val kek = kit.deriveKek(RecoveryKit.splitWords(File(fixture, "phrase.txt").readText().toCharArray()), File(security, "vault_salt.public").readBytes())
        kit.openBackup(File(security, "rmk_backup.bin").readBytes(), kek).use { vault ->
            val vaultId = expected["vaultId"]!!.jsonPrimitive.content
            SharedFolderRecovery.openAsMember(manifest, vaultId, vault.rootKey, identity).use { checkFolder(manifest, it) }
            assertThrows(IllegalArgumentException::class.java) { SharedFolderRecovery.openAsMember(manifest, "vault-nobody", vault.rootKey, identity) }
            // Another vault's root does not open this identity.
            assertThrows(IllegalArgumentException::class.java) { SharedFolderRecovery.openAsMember(manifest, vaultId, ByteArray(32) { 1 }, identity) }
        }
    }

    @Test
    fun `the recovery tool recovers the folder with the kits`() {
        val out = temp.newFolder()
        val log = java.io.ByteArrayOutputStream()
        val code = com.sino.sdk.cli.SinoDecryptorCLI.run(
            arrayOf("share-recover", "--share", folder.path, "--out", out.path, "--include-trashed", "--kit", File(org, "kit-1.sinokit").path, "--kit", File(org, "kit-3-paper.txt").path),
            java.io.PrintStream(log), java.io.ByteArrayInputStream(ByteArray(0)),
        )
        assertEquals(log.toString(), com.sino.sdk.cli.SinoDecryptorCLI.EXIT_OK, code)
        assertEquals(map("files") + map("trash"), tree(out))
    }

    @Test
    fun `a changed batch is left out, and a changed file does not extract`() {
        val manifest = SharedFolderRecovery.readManifest(folder)
        val copy = temp.newFolder().also { folder.copyRecursively(it) }
        val batch = File(copy, "metadata").listFiles()!!.first()
        // Its envelope names a later sequence than the one its writer signed.
        batch.writeText(Regex("\"sequence\":(\\d+)").replace(batch.readText()) { "\"sequence\":" + (it.groupValues[1].toLong() + 1) })
        kits().use { orgKeys ->
            SharedFolderRecovery.openWithKits(manifest, orgKeys).use { keys ->
                val index = SharedFolderRecovery.index(copy, manifest, keys)
                assertEquals("A batch whose signature fails is refused", 1, index.refusedBatches)
                val clean = SharedFolderRecovery.index(folder, manifest, keys)
                val file = clean.files.first()
                val blob = File(copy, file.entry.blobName)
                blob.writeBytes(blob.readBytes().also { it[it.size / 2] = (it[it.size / 2].toInt() xor 1).toByte() })
                assertThrows(Exception::class.java) { SharedFolderRecovery.extract(copy, file.entry, keys, File(temp.root, "out.bin")) }
            }
        }
        // Kits of another organisation open nothing.
        val other = manifest.copy(orgId = "org-other")
        kits().use { orgKeys -> assertThrows(IllegalArgumentException::class.java) { SharedFolderRecovery.openWithKits(other, orgKeys) } }
    }
}
