package com.sino.sdk.org

import com.sino.sdk.crypto.AESEncryptionEngine
import com.sino.sdk.crypto.CryptoConstants
import com.sino.sdk.crypto.HKDFEngine
import com.sino.sdk.crypto.MLDSAEngine
import com.sino.sdk.crypto.MLKEMEngine
import com.sino.sdk.crypto.SecurityUtils
import com.sino.sdk.crypto.SinoKeyDerivation
import com.sino.sdk.vault.RecoveryKit
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

/**
 * Recovery of a managed vault without Sino or its hub (SPECIFICATION.md §12): a quorum of the organisation's kits
 * rebuilds its recovery key, which opens the vault's recovery file (`SINO-ORG-RECOVERY`), giving the vault's root key
 * and salt; the vault then opens as from a recovery phrase ([com.sino.sdk.vault.VaultRecovery.openWithKeys]).
 *
 * Everything is checked as Sino checks it: a full kit's ML-DSA-65 signature by the root key, the kits' fields
 * matching, and a check value after combining (the sealed RSA key must open, and the derived keys must match the
 * kits' public keys or, for paper kits, their root fingerprint).
 *
 * When the RSA half of the recovery key is in the organisation's HSM (`rsaKeyInHsm`), the kits hold no RSA private
 * key: opening asks for the HSM's answer ([HsmAnswerNeededException]), which [OrganisationKeys.answerHsm] takes.
 */
object OrganisationRecovery {

    /** Where the RSA half of the recovery key is, when an HSM holds it: its label there and its public key (base64 SPKI). */
    @Serializable
    data class HsmKey(val label: String, val publicKeySpkiBase64: String)

    /**
     * The HSM must decrypt [ciphertextBase64] (RSA-OAEP, SHA-256, MGF1-SHA-256) with its key [keyLabel]; give its answer
     * (base64 of 32 bytes) to [OrganisationKeys.answerHsm] and open again.
     */
    class HsmAnswerNeededException(val ciphertextBase64: String, val keyLabel: String) :
        IllegalArgumentException("The recovery key's RSA half is in the organisation's HSM: have key \"$keyLabel\" decrypt $ciphertextBase64 (RSA-OAEP, SHA-256, MGF1-SHA-256) and give its answer")

    // --- Formats (field order and names as Sino writes them) -----------------------------------------------------------

    @Serializable
    internal data class Kit(
        val format: String, val version: Int, val orgId: String, val orgName: String, val kitSetId: String, val createdAt: Long,
        val holder: String, val threshold: Int, val shareCount: Int, val shareIndex: Int, val shareBase64: String,
        val rootPublicKeyBase64: String, val recoveryPublicKey: String, val sealedRsaPrivateKeyBase64: String,
        val rsaKeyInHsm: HsmKey? = null,
        val signatureBase64: String? = null,
    )

    @Serializable
    internal data class PaperKit(
        val format: String, val version: Int, val orgId: String, val orgName: String, val kitSetId: String, val createdAt: Long,
        val holder: String, val threshold: Int, val shareCount: Int, val shareIndex: Int, val shareBase64: String,
        val rootFingerprint: String, val sealedRsaPrivateKeyBase64: String,
        val rsaKeyInHsm: HsmKey? = null,
    )

    @Serializable
    internal data class SealedKit(
        val format: String, val version: Int, val content: String, val orgId: String, val orgName: String, val kitSetId: String,
        val holder: String, val shareIndex: Int, val shareCount: Int, val threshold: Int, val saltBase64: String, val sealedBase64: String,
    )

    @Serializable
    internal data class Blob(
        val format: String, val version: Int, val orgId: String, val vaultId: String, val kitSetId: String, val deviceId: String,
        val createdAt: Long, val sealedBase64: String,
    )

    private val json = Json { encodeDefaults = true }

    private const val KIT = "SINO-ORG-KIT"
    private const val PAPER = "SINO-ORG-PAPER-KIT"
    private const val SEALED = "SINO-ORG-KIT-SEALED"
    private const val BLOB = "SINO-ORG-RECOVERY"
    private const val CODE_PREFIX = "SINOKIT1:"
    private val SET_ID = Regex("^[0-9a-f]{32}$")

    /** One kit as brought: its header and share, and what it says about the organisation's keys. */
    class OrgKit internal constructor(
        val orgId: String,
        val orgName: String,
        val kitSetId: String,
        val holder: String,
        val threshold: Int,
        val shareCount: Int,
        val shareIndex: Int,
        internal val share: ByteArray,
        internal val sealedRsa: ByteArray,
        /** A full kit's public keys; null for a paper kit. */
        internal val rootPublicKey: ByteArray?,
        internal val recoveryPublicKey: String?,
        /** A paper kit's root fingerprint; for a full kit, the fingerprint of its root key. */
        internal val rootFingerprint: String,
        /** The HSM holding the RSA half, if one does; [sealedRsa] is then empty. */
        val hsm: HsmKey? = null,
    ) {
        /** Matches another kit of the same ceremony: everything but holder, index and share. */
        internal fun sameSetAs(other: OrgKit) = orgId == other.orgId && orgName == other.orgName && kitSetId == other.kitSetId &&
            threshold == other.threshold && shareCount == other.shareCount && rootFingerprint == other.rootFingerprint &&
            sealedRsa.contentEquals(other.sealedRsa) && hsm == other.hsm
    }

    /** The kit asks for its passphrase: [holder] can be read without it. */
    class PassphraseNeededException(val holder: String) : IllegalArgumentException("$holder's kit is sealed with a passphrase")

    /**
     * Reads one kit: a `.sinokit` file (sealed with a passphrase or not), or a paper kit as the text of its scanned QR
     * codes, one per line, in any order. Throws [PassphraseNeededException] for a sealed kit without [passphrase], and
     * [IllegalArgumentException] for anything else that is not a valid kit (a wrong passphrase included).
     */
    fun readKit(text: String, passphrase: CharArray? = null, kdf: SinoKeyDerivation = SinoKeyDerivation()): OrgKit {
        val trimmed = text.trim()
        val content = if (trimmed.startsWith(CODE_PREFIX)) joinCodes(trimmed.lines().map { it.trim() }.filter { it.isNotEmpty() }) else trimmed
        val format = runCatching { Json.parseToJsonElement(content) }.getOrNull()
            ?.let { (it as? kotlinx.serialization.json.JsonObject)?.get("format") }
            ?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.content }
            ?: throw IllegalArgumentException("Not a Sino organisation kit")
        return when (format) {
            KIT -> fullKit(json.decodeFromString(Kit.serializer(), content))
            PAPER -> paperKit(json.decodeFromString(PaperKit.serializer(), content))
            SEALED -> {
                val sealed = json.decodeFromString(SealedKit.serializer(), content)
                val pass = passphrase ?: throw PassphraseNeededException(sealed.holder)
                val inner = openSealed(sealed, pass, kdf)
                val kit = when (sealed.content) {
                    KIT -> fullKit(json.decodeFromString(Kit.serializer(), inner))
                    PAPER -> paperKit(json.decodeFromString(PaperKit.serializer(), inner))
                    else -> throw IllegalArgumentException("Unknown sealed kit content")
                }
                // A changed header is refused like a changed ciphertext.
                require(
                    kit.orgId == sealed.orgId && kit.orgName == sealed.orgName && kit.kitSetId == sealed.kitSetId && kit.holder == sealed.holder &&
                        kit.shareIndex == sealed.shareIndex && kit.shareCount == sealed.shareCount && kit.threshold == sealed.threshold,
                ) { "The sealed kit's header does not match the kit inside" }
                kit
            }
            else -> throw IllegalArgumentException("Not a Sino organisation kit ($format)")
        }
    }

    /** The organisation's recovery key, rebuilt in memory. [close] erases it. */
    class OrganisationKeys internal constructor(
        val orgId: String,
        val kitSetId: String,
        /** Null when the RSA half is in the organisation's HSM ([hsm]). */
        internal val rsaPrivateKeyPkcs8: ByteArray?,
        internal val rsaPublicKeySpki: ByteArray,
        internal val kemSeed: ByteArray,
        internal val kemPublicKey: ByteArray,
        val hsm: HsmKey? = null,
    ) : AutoCloseable {
        private var hsmAnswer: ByteArray? = null

        /** The HSM's answer (base64 of the 32 bytes it decrypted) to the [HsmAnswerNeededException] opening threw. */
        fun answerHsm(base64: String) {
            val secret = SecurityUtils.fromBase64(base64.trim().toCharArray())
            require(secret.size == 32) { "The HSM's answer is 32 bytes, in base64" }
            hsmAnswer?.let { SecurityUtils.fillZero(it) }
            hsmAnswer = secret
        }

        /** The RSA half's decryption: with the key from the kits, or the HSM's answer. */
        internal fun rsaDecrypt(ciphertext: ByteArray): ByteArray {
            rsaPrivateKeyPkcs8?.let { return rsaDecrypt(ciphertext, it) }
            return hsmAnswer?.copyOf() ?: throw HsmAnswerNeededException(java.util.Base64.getEncoder().encodeToString(ciphertext), hsm!!.label)
        }

        override fun close() {
            SecurityUtils.fillZero(rsaPrivateKeyPkcs8)
            SecurityUtils.fillZero(kemSeed)
            SecurityUtils.fillZero(hsmAnswer)
        }
    }

    /** Combines [kits] (at least their threshold, distinct, of one ceremony) and checks the result. */
    fun open(kits: List<OrgKit>): OrganisationKeys {
        require(kits.isNotEmpty()) { "No kits" }
        val first = kits.first()
        require(kits.all { it.sameSetAs(first) }) { "These kits come from different ceremonies or organisations" }
        require(kits.map { it.shareIndex }.toSet().size == kits.size) { "The same kit was given twice" }
        require(kits.size >= first.threshold) { "${first.threshold} kits are needed; ${kits.size} were given" }

        val secret = combine(kits.map { it.shareIndex to it.share })
        val hkdf = HKDFEngine()
        val ctx = first.orgId + "|" + first.kitSetId
        var rsaKey: ByteArray? = null
        var xi: ByteArray? = null
        try {
            rsaKey = hkdf.derive(secret, "SINO/V1/ORG-KIT-RSA|$ctx", CryptoConstants.AES_KEY_SIZE)
            val sealed = first.sealedRsa
            // With the RSA half in an HSM, the kits name its public key and hold nothing to open.
            val rsaPrivate = if (first.hsm != null) null else try {
                AESEncryptionEngine().decrypt(sealed.copyOfRange(CryptoConstants.GCM_IV_SIZE, sealed.size), rsaKey, sealed.copyOfRange(0, CryptoConstants.GCM_IV_SIZE))
            } catch (e: Exception) {
                throw IllegalArgumentException("The kits do not fit together: one of them is wrong or damaged")
            }
            val kemSeed = hkdf.derive(secret, "SINO/V1/ORG-RECOVERY-KEM|$ctx", 64)
            val kem = MLKEMEngine().keyPairFromSeed(kemSeed)
            xi = hkdf.derive(secret, "SINO/V1/ORG-ROOT|$ctx", 32)
            val root = MLDSAEngine().keyPairFromSeed(xi)
            val fingerprintOk = fingerprint(root.publicKey) == first.rootFingerprint
            root.zeroize()
            val rsaPublic = rsaPrivate?.let(::rsaPublicKeyOf) ?: SecurityUtils.fromBase64(first.hsm!!.publicKeySpkiBase64.toCharArray())
            val keysMatch = kits.mapNotNull { it.recoveryPublicKey }.all { token ->
                val (spki, kemPublic) = recipient(token)
                spki.contentEquals(rsaPublic) && kemPublic.contentEquals(kem.publicKey) && hsmRecipient(token) == (first.hsm != null)
            }
            if (!fingerprintOk || !keysMatch) {
                SecurityUtils.fillZero(rsaPrivate)
                SecurityUtils.fillZero(kemSeed)
                throw IllegalArgumentException("The kits do not fit together: one of them is wrong or damaged")
            }
            return OrganisationKeys(first.orgId, first.kitSetId, rsaPrivate, rsaPublic, kemSeed, kem.publicKey, first.hsm)
        } finally {
            SecurityUtils.fillZero(secret)
            SecurityUtils.fillZero(rsaKey)
            SecurityUtils.fillZero(xi)
        }
    }

    /** The vault id a recovery file names. */
    fun vaultIdOf(recoveryFile: String): String = json.decodeFromString(Blob.serializer(), recoveryFile.trim()).vaultId

    /**
     * Opens a vault's recovery file with [keys]: the vault's root key and salt, as a recovery phrase would give them.
     * Throws [IllegalArgumentException] when it is another organisation's or kit set's, or does not open, and
     * [HsmAnswerNeededException] when the HSM has not answered yet.
     */
    fun openRecoveryFile(recoveryFile: String, keys: OrganisationKeys): RecoveryKit.RecoveredVault {
        val blob = json.decodeFromString(Blob.serializer(), recoveryFile.trim())
        require(blob.format == BLOB && blob.version == 1) { "Not a Sino recovery file" }
        require(blob.orgId == keys.orgId) { "This recovery file belongs to another organisation" }
        require(blob.kitSetId == keys.kitSetId) { "This vault was sealed to another kit set: bring the kits of set ${blob.kitSetId}" }
        val container = SecurityUtils.fromBase64(blob.sealedBase64.toCharArray())
        val buffer = ByteBuffer.wrap(container)
        require(container.size > 7 + MLKEMEngine.CIPHERTEXT_SIZE + 28) { "The recovery file is truncated" }
        val magic = ByteArray(4).also { buffer.get(it) }
        require(magic.contentEquals("SINO".encodeToByteArray()) && buffer.get().toInt() == 3) { "Unknown recovery container" }
        val rsaLength = buffer.short.toInt() and 0xFFFF
        require(rsaLength > 0 && buffer.remaining() > rsaLength + MLKEMEngine.CIPHERTEXT_SIZE + 28) { "The recovery file is truncated" }
        val rsaCt = ByteArray(rsaLength).also { buffer.get(it) }
        val kemCt = ByteArray(MLKEMEngine.CIPHERTEXT_SIZE).also { buffer.get(it) }
        val iv = ByteArray(CryptoConstants.GCM_IV_SIZE).also { buffer.get(it) }
        val sealed = ByteArray(buffer.remaining()).also { buffer.get(it) }

        var kemSecret: ByteArray? = null
        var rsaSecret: ByteArray? = null
        var ikm: ByteArray? = null
        var kek: ByteArray? = null
        var payload: ByteArray? = null
        try {
            kemSecret = MLKEMEngine().decapsulate(kemCt, keys.kemSeed)
            rsaSecret = keys.rsaDecrypt(rsaCt)
            require(rsaSecret.size == 32) { "The recovery file does not open with these kits" }
            val transcript = MessageDigest.getInstance("SHA-256").digest(kemCt + rsaCt + keys.rsaPublicKeySpki + keys.kemPublicKey)
            val domain = "SINO/V1/ORG-RECOVERY|${blob.orgId}|${blob.vaultId}|${blob.kitSetId}|" + SecurityUtils.toHex(transcript).concatToString()
            ikm = kemSecret + rsaSecret
            kek = HKDFEngine().derive(ikm, domain, CryptoConstants.AES_KEY_SIZE)
            payload = try {
                AESEncryptionEngine().decrypt(sealed, kek, iv)
            } catch (e: Exception) {
                throw IllegalArgumentException("The recovery file does not open with these kits: it was changed or damaged")
            }
            require(payload.size in 32 + 16..32 + 64) { "The recovery file holds no vault key" }
            return RecoveryKit.RecoveredVault(payload.copyOfRange(0, 32), payload.copyOfRange(32, payload.size))
        } catch (e: IllegalArgumentException) {
            throw e
        } catch (e: Exception) {
            throw IllegalArgumentException("The recovery file does not open with these kits")
        } finally {
            SecurityUtils.fillZero(kemSecret)
            SecurityUtils.fillZero(rsaSecret)
            SecurityUtils.fillZero(ikm)
            SecurityUtils.fillZero(kek)
            SecurityUtils.fillZero(payload)
        }
    }

    // --- Internals ------------------------------------------------------------------------------------------------------

    private fun fullKit(kit: Kit): OrgKit {
        require(kit.format == KIT && kit.version == 1) { "Unknown kit version" }
        checkHeader(kit.kitSetId, kit.holder, kit.threshold, kit.shareCount, kit.shareIndex)
        val root = SecurityUtils.fromBase64(kit.rootPublicKeyBase64.toCharArray())
        val unsigned = json.encodeToString(Kit.serializer(), kit.copy(signatureBase64 = null)).encodeToByteArray()
        val signature = kit.signatureBase64?.let { SecurityUtils.fromBase64(it.toCharArray()) } ?: throw IllegalArgumentException("The kit is not signed")
        require(MLDSAEngine().verify(unsigned, signature, root)) { "${kit.holder}'s kit was changed or damaged: its signature does not check out" }
        val (spki, _) = recipient(kit.recoveryPublicKey)
        kit.rsaKeyInHsm?.let { hsm ->
            require(kit.sealedRsaPrivateKeyBase64.isEmpty() && SecurityUtils.fromBase64(hsm.publicKeySpkiBase64.toCharArray()).contentEquals(spki)) {
                "${kit.holder}'s kit names an HSM key that is not its recovery key"
            }
        }
        return OrgKit(
            kit.orgId, kit.orgName, kit.kitSetId, kit.holder, kit.threshold, kit.shareCount, kit.shareIndex,
            share(kit.shareBase64), SecurityUtils.fromBase64(kit.sealedRsaPrivateKeyBase64.toCharArray()), root, kit.recoveryPublicKey, fingerprint(root),
            kit.rsaKeyInHsm,
        )
    }

    private fun paperKit(kit: PaperKit): OrgKit {
        require(kit.format == PAPER && kit.version == 1) { "Unknown paper kit version" }
        checkHeader(kit.kitSetId, kit.holder, kit.threshold, kit.shareCount, kit.shareIndex)
        require(kit.rootFingerprint.length == 43) { "Malformed root fingerprint" }
        require(kit.rsaKeyInHsm == null || kit.sealedRsaPrivateKeyBase64.isEmpty()) { "A paper kit with an HSM key holds no RSA key" }
        return OrgKit(
            kit.orgId, kit.orgName, kit.kitSetId, kit.holder, kit.threshold, kit.shareCount, kit.shareIndex,
            share(kit.shareBase64), SecurityUtils.fromBase64(kit.sealedRsaPrivateKeyBase64.toCharArray()), null, null, kit.rootFingerprint,
            kit.rsaKeyInHsm,
        )
    }

    private fun checkHeader(setId: String, holder: String, threshold: Int, count: Int, index: Int) {
        require(SET_ID.matches(setId)) { "Malformed kit set id" }
        require(holder.isNotBlank() && holder.length <= 64) { "Malformed holder" }
        require(count in 1..255 && threshold in 1..count && index in 1..count) { "Malformed share numbers" }
    }

    private fun share(base64: String): ByteArray =
        SecurityUtils.fromBase64(base64.toCharArray()).also { require(it.size == 32) { "Malformed share" } }

    private fun openSealed(sealed: SealedKit, passphrase: CharArray, kdf: SinoKeyDerivation): String {
        require(sealed.format == SEALED && sealed.version == 1) { "Unknown sealed kit version" }
        val salt = SecurityUtils.fromBase64(sealed.saltBase64.toCharArray()).also { require(it.size == 16) { "Malformed salt" } }
        val data = SecurityUtils.fromBase64(sealed.sealedBase64.toCharArray())
        var stretched: ByteArray? = null
        var key: ByteArray? = null
        var plain: ByteArray? = null
        try {
            stretched = kdf.deriveKey(passphrase, salt)
            key = HKDFEngine().derive(stretched, "SINO/V1/ORG-KIT-SEAL|" + sealed.kitSetId, CryptoConstants.AES_KEY_SIZE)
            plain = try {
                AESEncryptionEngine().decrypt(data.copyOfRange(CryptoConstants.GCM_IV_SIZE, data.size), key, data.copyOfRange(0, CryptoConstants.GCM_IV_SIZE))
            } catch (e: Exception) {
                throw IllegalArgumentException("The passphrase does not open ${sealed.holder}'s kit")
            }
            return plain.decodeToString()
        } finally {
            SecurityUtils.fillZero(stretched)
            SecurityUtils.fillZero(key)
            SecurityUtils.fillZero(plain)
        }
    }

    /** `SINOKIT1:<part>/<parts>:<set id>:<text>` codes back into the kit's text; any order, duplicates allowed. */
    private fun joinCodes(codes: List<String>): String {
        var total = -1
        var setId: String? = null
        val parts = HashMap<Int, String>()
        for (code in codes) {
            require(code.startsWith(CODE_PREFIX)) { "Not a Sino kit code" }
            val rest = code.removePrefix(CODE_PREFIX)
            val position = rest.substringBefore(':')
            val afterPosition = rest.substringAfter(':', "")
            val id = afterPosition.substringBefore(':')
            val chunk = afterPosition.substringAfter(':', "")
            val part = position.substringBefore('/').toIntOrNull() ?: throw IllegalArgumentException("Malformed kit code")
            val count = position.substringAfter('/', "").toIntOrNull() ?: throw IllegalArgumentException("Malformed kit code")
            require(count in 1..64 && part in 1..count && chunk.isNotEmpty()) { "Malformed kit code" }
            require(total == -1 || (count == total && id == setId)) { "These codes come from different kits" }
            total = count
            setId = id
            require(parts[part]?.let { it == chunk } != false) { "Two different codes claim the same part" }
            parts[part] = chunk
        }
        require(total != -1 && parts.size == total) { "Some of the kit's codes are missing" }
        return (1..total).joinToString("") { parts.getValue(it) }
    }

    /** Shamir over GF(2^8) (the AES field): the secret is the polynomial at x = 0 (Lagrange). */
    internal fun combine(shares: List<Pair<Int, ByteArray>>): ByteArray {
        val size = shares.first().second.size
        val basis = IntArray(shares.size) { j ->
            var numerator = 1
            var denominator = 1
            for (m in shares.indices) {
                if (m == j) continue
                numerator = multiply(numerator, shares[m].first)
                denominator = multiply(denominator, shares[m].first xor shares[j].first)
            }
            multiply(numerator, inverse(denominator))
        }
        return ByteArray(size) { b ->
            var value = 0
            for (j in shares.indices) value = value xor multiply(shares[j].second[b].toInt() and 0xFF, basis[j])
            value.toByte()
        }
    }

    private fun multiply(a: Int, b: Int): Int {
        var x = a
        var y = b
        var product = 0
        repeat(8) {
            product = product xor (x and -(y and 1))
            val carry = -((x shr 7) and 1)
            x = ((x shl 1) xor (0x1B and carry)) and 0xFF
            y = y shr 1
        }
        return product
    }

    private fun inverse(a: Int): Int {
        var result = 1
        var base = a
        var exponent = 254
        repeat(8) {
            if (exponent and 1 == 1) result = multiply(result, base)
            base = multiply(base, base)
            exponent = exponent shr 1
        }
        return result
    }

    /** Base64url (no padding) SHA-256 of a root key, as enrollment links and paper kits name it. */
    private fun fingerprint(rootPublicKey: ByteArray): String =
        SecurityUtils.toBase64(MessageDigest.getInstance("SHA-256").digest(rootPublicKey), urlSafe = true, pad = false).concatToString()

    /**
     * A recipient token: base64url of `[version][u16 rsa length][RSA SPKI][ML-KEM-768 public key]`; version 1, or 2 for
     * an RSA key in an HSM (OAEP with MGF1-SHA-256).
     */
    internal fun recipient(token: String): Pair<ByteArray, ByteArray> {
        val bytes = SecurityUtils.fromBase64(token.trim().toCharArray(), urlSafe = true)
        require(bytes.size > 3 && (bytes[0].toInt() == 1 || bytes[0].toInt() == 2)) { "Unknown recovery key version" }
        val rsaLength = ((bytes[1].toInt() and 0xFF) shl 8) or (bytes[2].toInt() and 0xFF)
        require(bytes.size == 3 + rsaLength + MLKEMEngine.PUBLIC_KEY_SIZE) { "Malformed recovery key" }
        return bytes.copyOfRange(3, 3 + rsaLength) to bytes.copyOfRange(3 + rsaLength, bytes.size)
    }

    /** True for a version 2 recipient token: its RSA key is in an HSM. */
    private fun hsmRecipient(token: String): Boolean = SecurityUtils.fromBase64(token.trim().toCharArray(), urlSafe = true)[0].toInt() == 2

    private fun rsaPublicKeyOf(pkcs8: ByteArray): ByteArray {
        val factory = KeyFactory.getInstance("RSA")
        val private = factory.generatePrivate(PKCS8EncodedKeySpec(pkcs8)) as java.security.interfaces.RSAPrivateCrtKey
        return factory.generatePublic(java.security.spec.RSAPublicKeySpec(private.modulus, private.publicExponent)).encoded
    }

    /** RSA-OAEP with SHA-256 and MGF1-SHA-1, stated explicitly, as Sino uses it. */
    internal fun rsaDecrypt(ciphertext: ByteArray, pkcs8: ByteArray): ByteArray {
        val key = KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(pkcs8))
        val cipher = Cipher.getInstance("RSA/ECB/OAEPPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT))
        return cipher.doFinal(ciphertext)
    }
}
