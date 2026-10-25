package com.sino.sdk.org

import com.sino.sdk.cli.SinoDecryptorCLI
import com.sino.sdk.crypto.SecurityUtils
import com.sino.sdk.vault.VaultRecovery
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.PrintStream
import java.security.MessageDigest

/**
 * A managed vault recovered without Sino (SPECIFICATION.md §12), against the fixture Sino's own core wrote
 * (`fixtures/core-vault/org`): kits of a 2-of-3 ceremony (one plain, one sealed with a passphrase, one on paper) and
 * the vault's recovery file, for the same vault as the recovery-phrase fixture.
 */
class OrganisationRecoveryInteropTest {

    @get:Rule
    val temp = TemporaryFolder()

    private val fixture = File(javaClass.getResource("/fixtures/core-vault")!!.toURI())
    private val org = File(fixture, "org")
    private val providers = listOf(File(fixture, "provider-a"), File(fixture, "provider-b"))
    private val kit1 = File(org, "kit-1.sinokit").readText()
    private val kit2 = File(org, "kit-2-sealed.sinokit").readText()
    private val kit3 = File(org, "kit-3-paper.txt").readText()
    private val recoveryFile = File(org, "recovery.sinorecovery").readText()
    private val passphrase = File(org, "kit-2.passphrase").readText().trim()

    private val expected = Json.parseToJsonElement(File(fixture, "expected.json").readText()).jsonObject["files"]!!.jsonObject
        .mapValues { it.value.jsonPrimitive.content }

    private fun sha256(file: File) = SecurityUtils.toHex(MessageDigest.getInstance("SHA-256").digest(file.readBytes())).concatToString()

    private fun recoverWith(kits: List<OrganisationRecovery.OrgKit>): Map<String, String> {
        val out = temp.newFolder()
        OrganisationRecovery.open(kits).use { keys ->
            OrganisationRecovery.openRecoveryFile(recoveryFile, keys).use { vault ->
                VaultRecovery.openWithKeys(providers, vault.rootKey, vault.vaultSalt).use { it.recover(out) }
            }
        }
        return out.walkTopDown().filter { it.isFile }.associate { it.relativeTo(out).invariantSeparatorsPath to sha256(it) }
    }

    @Test
    fun `two kits, one sealed with its passphrase, recover every file of the vault`() {
        val kits = listOf(OrganisationRecovery.readKit(kit1), OrganisationRecovery.readKit(kit2, passphrase.toCharArray()))
        assertEquals(expected, recoverWith(kits))
    }

    @Test
    fun `a paper kit's scanned codes, in any order, work with a full kit`() {
        val shuffled = kit3.lines().filter { it.isNotBlank() }.reversed().joinToString("\n")
        val paper = OrganisationRecovery.readKit(shuffled)
        assertEquals("Carol", paper.holder)
        assertEquals(expected, recoverWith(listOf(paper, OrganisationRecovery.readKit(kit1))))
    }

    @Test
    fun `kits are checked as Sino checks them`() {
        val one = OrganisationRecovery.readKit(kit1)
        assertThrows(IllegalArgumentException::class.java) { OrganisationRecovery.open(listOf(one)) } // below the threshold
        assertThrows(IllegalArgumentException::class.java) { OrganisationRecovery.open(listOf(one, one)) } // the same kit twice
        val needed = assertThrows(OrganisationRecovery.PassphraseNeededException::class.java) { OrganisationRecovery.readKit(kit2) }
        assertEquals("Bob", needed.holder)
        assertThrows(IllegalArgumentException::class.java) { OrganisationRecovery.readKit(kit2, "not the passphrase".toCharArray()) }
        val altered = kit1.replace("\"holder\":\"Alice\"", "\"holder\":\"Mallory\"")
        assertTrue(altered != kit1)
        val refused = assertThrows(IllegalArgumentException::class.java) { OrganisationRecovery.readKit(altered) }
        assertTrue(refused.message, "signature" in refused.message!!)
        assertThrows(IllegalArgumentException::class.java) { OrganisationRecovery.readKit(kit3.lines().first()) } // codes missing
    }

    @Test
    fun `the recovery file opens only as the vault it names`() {
        val kits = listOf(OrganisationRecovery.readKit(kit1), OrganisationRecovery.readKit(kit3))
        assertEquals("vault-fixture", OrganisationRecovery.vaultIdOf(recoveryFile))
        OrganisationRecovery.open(kits).use { keys ->
            val moved = recoveryFile.replace("\"vaultId\":\"vault-fixture\"", "\"vaultId\":\"vault-other\"")
            assertThrows(IllegalArgumentException::class.java) { OrganisationRecovery.openRecoveryFile(moved, keys) }
            val otherSet = recoveryFile.replace(Regex("\"kitSetId\":\"[0-9a-f]{32}\""), "\"kitSetId\":\"${"a".repeat(32)}\"")
            assertThrows(IllegalArgumentException::class.java) { OrganisationRecovery.openRecoveryFile(otherSet, keys) }
        }
    }

    @Test
    fun `the recovery tool recovers with the recovery file and two kits`() {
        val passphrases = temp.newFile().apply { writeText(passphrase + "\n") }
        val k1 = File(org, "kit-1.sinokit").path
        val k2 = File(org, "kit-2-sealed.sinokit").path
        val out = temp.newFolder("out")
        val bytes = ByteArrayOutputStream()
        val code = SinoDecryptorCLI.run(
            arrayOf(
                "recover", "--vault", providers[0].path, "--vault", providers[1].path, "--out", out.path,
                "--recovery-file", File(org, "recovery.sinorecovery").path, "--kit", k1, "--kit", k2, "--kit-passphrases", passphrases.path,
            ),
            PrintStream(bytes, true, "UTF-8"), ByteArrayInputStream(ByteArray(0)),
        )
        val text = bytes.toString("UTF-8")
        assertEquals(text, SinoDecryptorCLI.EXIT_OK, code)
        assertTrue(text, "Recovered 6 file(s)" in text)
        assertTrue("The passphrase never appears in the output", passphrase !in text)

        val mixed = SinoDecryptorCLI.run(
            arrayOf("list", "--vault", providers[0].path, "--recovery-file", File(org, "recovery.sinorecovery").path, "--kit", k1, "--phrase-stdin"),
            PrintStream(ByteArrayOutputStream()), ByteArrayInputStream(ByteArray(0)),
        )
        assertEquals(SinoDecryptorCLI.EXIT_ERROR, mixed)
        val tooFew = SinoDecryptorCLI.run(
            arrayOf("list", "--vault", providers[0].path, "--recovery-file", File(org, "recovery.sinorecovery").path, "--kit", k1),
            PrintStream(ByteArrayOutputStream()), ByteArrayInputStream(ByteArray(0)),
        )
        assertEquals(SinoDecryptorCLI.EXIT_ERROR, tooFew)
    }

    // --- The recovery key's RSA half in the organisation's HSM (fixtures/core-vault/org-hsm) ---

    private val hsmOrg = File(fixture, "org-hsm")

    /** What the HSM does: RSA-OAEP with SHA-256 and MGF1-SHA-256, with the key the fixture's test-only file holds. */
    private fun hsmDecrypts(ciphertextBase64: String): String {
        val key = java.security.KeyFactory.getInstance("RSA").generatePrivate(java.security.spec.PKCS8EncodedKeySpec(File(hsmOrg, "hsm-test-only.pk8").readBytes()))
        val cipher = javax.crypto.Cipher.getInstance("RSA/ECB/OAEPPadding")
        cipher.init(
            javax.crypto.Cipher.DECRYPT_MODE, key,
            javax.crypto.spec.OAEPParameterSpec("SHA-256", "MGF1", java.security.spec.MGF1ParameterSpec.SHA256, javax.crypto.spec.PSource.PSpecified.DEFAULT),
        )
        return java.util.Base64.getEncoder().encodeToString(cipher.doFinal(java.util.Base64.getDecoder().decode(ciphertextBase64)))
    }

    @Test
    fun `with the RSA half in an HSM, the kits and the HSM's answer recover the vault, and neither alone`() {
        val kits = listOf(
            OrganisationRecovery.readKit(File(hsmOrg, "kit-1.sinokit").readText()),
            OrganisationRecovery.readKit(File(hsmOrg, "kit-2-paper.txt").readText()),
        )
        assertEquals("sino-recovery", kits[0].hsm?.label)
        assertEquals(kits[0].hsm, kits[1].hsm)
        val file = File(hsmOrg, "recovery.sinorecovery").readText()
        val out = temp.newFolder()
        OrganisationRecovery.open(kits).use { keys ->
            val needed = assertThrows(OrganisationRecovery.HsmAnswerNeededException::class.java) { OrganisationRecovery.openRecoveryFile(file, keys) }
            assertEquals("sino-recovery", needed.keyLabel)
            keys.answerHsm(java.util.Base64.getEncoder().encodeToString(ByteArray(32)))
            assertThrows(IllegalArgumentException::class.java) { OrganisationRecovery.openRecoveryFile(file, keys) } // a wrong answer
            assertThrows(IllegalArgumentException::class.java) { keys.answerHsm("AAAA") } // not 32 bytes
            keys.answerHsm(hsmDecrypts(needed.ciphertextBase64))
            OrganisationRecovery.openRecoveryFile(file, keys).use { vault ->
                VaultRecovery.openWithKeys(providers, vault.rootKey, vault.vaultSalt).use { it.recover(out) }
            }
        }
        val recovered = out.walkTopDown().filter { it.isFile }.associate { it.relativeTo(out).invariantSeparatorsPath to sha256(it) }
        assertEquals(expected, recovered)
        // An HSM kit's reference is signed with the rest of the kit.
        val altered = File(hsmOrg, "kit-1.sinokit").readText().replace("\"label\":\"sino-recovery\"", "\"label\":\"other\"")
        assertThrows(IllegalArgumentException::class.java) { OrganisationRecovery.readKit(altered) }
    }

    @Test
    fun `the recovery tool prints what the HSM must decrypt, then takes its answer`() {
        val args = arrayOf(
            "list", "--vault", providers[0].path, "--vault", providers[1].path, "--recovery-file", File(hsmOrg, "recovery.sinorecovery").path,
            "--kit", File(hsmOrg, "kit-1.sinokit").path, "--kit", File(hsmOrg, "kit-2-paper.txt").path,
        )
        val first = ByteArrayOutputStream()
        assertEquals(SinoDecryptorCLI.EXIT_ERROR, SinoDecryptorCLI.run(args, PrintStream(first, true, "UTF-8"), ByteArrayInputStream(ByteArray(0))))
        val asked = first.toString("UTF-8")
        val ciphertext = Regex("decrypt ([A-Za-z0-9+/=]+)").find(asked)?.groupValues?.get(1)
        assertTrue(asked, ciphertext != null && "sino-recovery" in asked)
        val second = ByteArrayOutputStream()
        val code = SinoDecryptorCLI.run(args + arrayOf("--hsm-answer", hsmDecrypts(ciphertext!!)), PrintStream(second, true, "UTF-8"), ByteArrayInputStream(ByteArray(0)))
        assertEquals(second.toString("UTF-8"), SinoDecryptorCLI.EXIT_OK, code)
    }
}
