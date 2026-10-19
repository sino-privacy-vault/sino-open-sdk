package com.sino.sdk.share

import com.sino.sdk.crypto.AESEncryptionEngine
import com.sino.sdk.crypto.CryptoConstants
import com.sino.sdk.crypto.HKDFEngine
import com.sino.sdk.crypto.MLDSAEngine
import com.sino.sdk.crypto.MLKEMEngine
import com.sino.sdk.crypto.SecurityUtils
import com.sino.sdk.org.OrganisationRecovery
import com.sino.sdk.vault.VaultKeys
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.security.DigestOutputStream
import java.security.MessageDigest
import java.time.Instant
import java.time.ZoneOffset

/**
 * Reading a Sino shared folder without Sino or its hub (SPECIFICATION.md §13): from a copy of the folder's storage
 * (`shares/<share id>/`), either with a quorum of the organisation's kits (its manifest's organisation copy) or as a
 * member, with the member vault's root key and its sealed identity (`security/share_identity.bin`).
 *
 * As in Sino: each metadata batch counts only when its writer is an owner or editor of the manifest and its ML-DSA-65
 * signature verifies; revisions merge by their version vectors, and two that do not replace each other are both kept,
 * the later one under a conflict name; files sit in subfolders (folder entries), recovered as directories. The manifest itself is taken as given: Sino's apps check its chain of versions
 * against the hub, which a copy of the storage does not hold.
 */
object SharedFolderRecovery {

    // --- Formats (field order and names as Sino writes them) -----------------------------------------------------------

    @Serializable
    data class Member(val vaultId: String, val role: String, val signerBase64: String, val receiver: String)

    @Serializable
    data class KeyEntry(val vaultId: String, val sealedBase64: String)

    @Serializable
    data class Manifest(
        val format: String, val version: Int, val orgId: String, val shareId: String, val manifestVersion: Long, val epoch: Int,
        val previousHash: String, val nameBase64: String, val members: List<Member>, val keys: List<KeyEntry>,
        val kitSetId: String?, val orgRecoveryBase64: String?, val issuedAt: Long, val signedBy: String, val signatureBase64: String? = null,
    )

    @Serializable
    internal data class KeyBundle(val shareId: String, val epoch: Int, val saltBase64: String, val keysBase64: List<String>)

    @Serializable
    internal data class IdentitySecret(
        val format: String, val version: Int, val kemSeedBase64: String, val rsaPrivateKeyPkcs8Base64: String, val rsaPublicKeySpkiBase64: String,
    )

    @Serializable
    data class Entry(
        val fileId: String, val revisionId: String, val name: String, val mimeType: String, val size: Long, val checksum: String,
        val modifiedAt: Long, val author: String, val clock: Map<String, Long>, val keyEpoch: Int, val wrappedDekBase64: String,
        val ivBase64: String, val encryptionVersion: Int = CryptoConstants.CHUNK_FORMAT_VERSION, val blobName: String,
        val trashed: Boolean = false, val deleted: Boolean = false, val parentId: String = "", val folder: Boolean = false,
    )

    /** Content a writer replaced, waiting out its grace period before the writer deletes it: not needed to recover. */
    @Serializable
    data class Retired(val blobName: String, val since: Long)

    /** A writer editing a file outside Sino: a hint for the other members, not needed to recover the folder. */
    @Serializable
    data class EditMark(val fileId: String, val revisionId: String, val baseClock: Map<String, Long>, val since: Long, val until: Long)

    @Serializable
    internal data class Batch(
        val shareId: String, val writer: String, val sequence: Long, val writtenAt: Long, val entries: List<Entry>,
        val editing: List<EditMark> = emptyList(), val retired: List<Retired> = emptyList(),
    )

    @Serializable
    internal data class Envelope(
        val format: String, val version: Int, val shareId: String, val writer: String, val sequence: Long, val epoch: Int,
        val sealedBase64: String, val signatureBase64: String? = null,
    )

    private val json = Json { encodeDefaults = true }
    private const val MANIFEST = "share_manifest.json"
    private const val METADATA = "metadata"
    private const val IDENTITY_DOMAIN = "SINO/V1/SHARE-IDENTITY"

    /** A folder's salt and share keys, epoch 1 first. [close] erases them. */
    class ShareKeys internal constructor(val shareId: String, internal val salt: ByteArray, internal val keys: List<ByteArray>) : AutoCloseable {
        val epoch: Int get() = keys.size

        internal fun key(epoch: Int): ByteArray {
            require(epoch in 1..keys.size) { "No share key for epoch $epoch" }
            return keys[epoch - 1]
        }

        internal fun domainKey(epoch: Int, domain: String): ByteArray =
            javax.crypto.Mac.getInstance("HmacSHA256").run {
                init(javax.crypto.spec.SecretKeySpec(key(epoch), "HmacSHA256"))
                update(domain.encodeToByteArray())
                update(0x01.toByte())
                doFinal()
            }

        override fun close() {
            SecurityUtils.fillZero(salt)
            keys.forEach { SecurityUtils.fillZero(it) }
        }
    }

    /**
     * A file as the folder shows it: its newest revision, or one side of a conflict. [path] is where it sits, its
     * subfolders' names and its own joined by "/" (`Plans/2026/q1.txt`).
     */
    class SharedFile(val displayName: String, val entry: Entry, val conflict: Boolean, val path: String = displayName)

    /** The folder's files and those in its trash (with what is inside a trashed subfolder), and its subfolders' paths. */
    class FolderIndex(
        val name: String, val files: List<SharedFile>, val trash: List<SharedFile>, val refusedBatches: Int,
        val folders: List<String> = emptyList(),
    )

    /** The folder's manifest, at the root of its copy. */
    fun readManifest(folder: File): Manifest {
        val manifest = json.decodeFromString(Manifest.serializer(), File(folder, MANIFEST).readText())
        require(manifest.format == "SINO-SHARE-MANIFEST" && manifest.version == 1) { "Not a Sino shared folder manifest" }
        return manifest
    }

    /** The folder's keys from its organisation copy, with the organisation's [keys] (rebuilt from a quorum of kits). */
    fun openWithKits(manifest: Manifest, keys: OrganisationRecovery.OrganisationKeys): ShareKeys {
        require(manifest.orgId == keys.orgId) { "This folder belongs to another organisation" }
        val kitSet = requireNotNull(manifest.kitSetId) { "This folder has no organisation copy" }
        require(kitSet == keys.kitSetId) { "This folder is sealed to kit set $kitSet: bring those kits" }
        val sealed = requireNotNull(manifest.orgRecoveryBase64) { "This folder has no organisation copy" }
        val domain = "SINO/V1/SHARE-ORG-RECOVERY|${manifest.orgId}|${manifest.shareId}|${manifest.epoch}|$kitSet|"
        val plain = openHybrid(base64(sealed), domain, keys.rsaPrivateKeyPkcs8, keys.rsaPublicKeySpki, keys.kemSeed, keys.kemPublicKey)
        return bundle(manifest, plain)
    }

    /**
     * The folder's keys as member [vaultId]: the vault's [rootKey] (from its recovery phrase or kits) opens its sealed
     * identity, [identityFile] (`security/share_identity.bin` in the vault's storage), whose receiving key opens the
     * member's bundle.
     */
    fun openAsMember(manifest: Manifest, vaultId: String, rootKey: ByteArray, identityFile: ByteArray): ShareKeys {
        val entry = requireNotNull(manifest.keys.firstOrNull { it.vaultId == vaultId }) { "Vault $vaultId is not a member of this folder" }
        val identityKey = VaultKeys(rootKey).use { it.domainKey(IDENTITY_DOMAIN) }
        val secretJson = try {
            require(identityFile.size > CryptoConstants.GCM_IV_SIZE + CryptoConstants.GCM_TAG_SIZE) { "The identity file is truncated" }
            AESEncryptionEngine().decrypt(identityFile.copyOfRange(CryptoConstants.GCM_IV_SIZE, identityFile.size), identityKey, identityFile.copyOfRange(0, CryptoConstants.GCM_IV_SIZE))
        } catch (e: IllegalArgumentException) {
            throw e
        } catch (e: Exception) {
            throw IllegalArgumentException("The identity file does not open with this vault's key")
        } finally {
            SecurityUtils.fillZero(identityKey)
        }
        val secret = json.decodeFromString(IdentitySecret.serializer(), secretJson.decodeToString())
        SecurityUtils.fillZero(secretJson)
        require(secret.format == "SINO-SHARE-IDENTITY" && secret.version == 1) { "Unknown identity format" }
        val seed = base64(secret.kemSeedBase64)
        val rsaPrivate = base64(secret.rsaPrivateKeyPkcs8Base64)
        try {
            val kem = MLKEMEngine().keyPairFromSeed(seed)
            val domain = "SINO/V1/SHARE-KEYS|${manifest.shareId}|$vaultId|${manifest.epoch}|"
            val plain = openHybrid(base64(entry.sealedBase64), domain, rsaPrivate, base64(secret.rsaPublicKeySpkiBase64), seed, kem.publicKey)
            return bundle(manifest, plain)
        } finally {
            SecurityUtils.fillZero(seed)
            SecurityUtils.fillZero(rsaPrivate)
        }
    }

    /** The folder's name, and its files merged from every batch its owners and editors signed. */
    fun index(folder: File, manifest: Manifest, keys: ShareKeys): FolderIndex {
        val writers = manifest.members.filter { it.role == "OWNER" || it.role == "EDITOR" }.associateBy { it.vaultId }
        var refused = 0
        val entries = mutableListOf<Entry>()
        File(folder, METADATA).listFiles { f -> f.name.endsWith(".batch") }?.sortedBy { it.name }?.forEach { file ->
            val batch = runCatching { openBatch(file, manifest, keys, writers) }.getOrNull()
            if (batch == null) refused++ else entries += batch.entries
        }
        val heads = entries.distinctBy { it.revisionId }.groupBy { it.fileId }.mapValues { (_, revisions) ->
            revisions.filter { r -> revisions.none { o -> o.revisionId != r.revisionId && dominates(o.clock, r.clock) } }
        }
        val tree = Tree(heads)
        val files = mutableListOf<SharedFile>()
        val trash = mutableListOf<SharedFile>()
        for ((fileId, revisions) in heads) {
            if (fileId in tree.folders) continue
            val live = revisions.filter { !it.deleted && !it.folder }
            val shown = live.filter { !it.trashed }.ifEmpty { live }.sortedWith(compareBy<Entry> { it.modifiedAt }.thenBy { it.revisionId })
            shown.forEachIndexed { i, entry ->
                val displayName = if (i == 0) entry.name else conflictName(entry)
                val file = SharedFile(displayName, entry, shown.size > 1, tree.pathOf(entry, displayName))
                // What is inside a subfolder in the trash is in the trash too.
                if (entry.trashed || tree.insideTrash(entry)) trash += file else files += file
            }
        }
        val name = openName(manifest, keys)
        val folders = tree.folders.values.map { tree.pathOf(it, it.name) }.sortedBy { it.lowercase() }
        return FolderIndex(name, files.sortedBy { it.path.lowercase() }, trash.sortedBy { it.path.lowercase() }, refused, folders)
    }

    /**
     * The subfolders, as Sino places them: each folder's revision that counts (one not in the trash, then the latest);
     * an entry whose folder is gone, or a folder caught in a loop of moves, sits at the top.
     */
    private class Tree(heads: Map<String, List<Entry>>) {
        val folders: Map<String, Entry> = heads.mapNotNull { (id, revisions) ->
            revisions.filter { it.folder && !it.deleted }
                .sortedWith(compareBy<Entry> { !it.trashed }.thenBy { it.modifiedAt }.thenBy { it.revisionId })
                .lastOrNull()?.let { id to it }
        }.toMap()

        private val cyclic: Set<String> = folders.keys.filter { start ->
            var at = folders[start]?.parentId
            var steps = 0
            while (!at.isNullOrEmpty() && at != start && steps++ <= folders.size) at = folders[at]?.parentId
            at == start
        }.toSet()

        fun parentOf(entry: Entry): String? =
            if (entry.folder && entry.fileId in cyclic) null else entry.parentId.takeIf { it.isNotEmpty() && it in folders }

        fun insideTrash(entry: Entry): Boolean = ancestors(entry).any { it.trashed }

        /** "Plans/2026/[name]": the names of the folders above [entry], then [name]. */
        fun pathOf(entry: Entry, name: String): String = (ancestors(entry).reversed().map { it.name } + name).joinToString("/")

        private fun ancestors(entry: Entry): List<Entry> {
            val out = mutableListOf<Entry>()
            var at = parentOf(entry)
            while (at != null && out.size <= folders.size) {
                val folder = folders.getValue(at)
                out += folder
                at = parentOf(folder)
            }
            return out
        }
    }

    /**
     * Writes every file of [index] (and its trash, with [includeTrashed]) into [outputDir], in directories as its
     * subfolders, each checked against its checksum. Returns the paths written ("/"-separated).
     */
    fun recover(folder: File, index: FolderIndex, keys: ShareKeys, outputDir: File, includeTrashed: Boolean = false): List<String> {
        outputDir.mkdirs()
        val written = mutableListOf<String>()
        for (file in index.files + if (includeTrashed) index.trash else emptyList()) {
            val parts = file.path.split('/')
            if (parts.any { !isSafeName(it) }) continue
            val target = File(outputDir, parts.joinToString(File.separator))
            target.parentFile.mkdirs()
            extract(folder, file.entry, keys, target)
            written += file.path
        }
        return written
    }

    /** Decrypts one file's content to [target], checked against its checksum; nothing is left behind on failure. */
    fun extract(folder: File, entry: Entry, keys: ShareKeys, target: File) {
        require(!entry.deleted && !entry.folder && entry.encryptionVersion == CryptoConstants.CHUNK_FORMAT_VERSION) { "No content to extract" }
        val blob = File(folder, entry.blobName)
        require(blob.isFile) { "The file's content is missing from the copy: ${entry.blobName}" }
        val wrapped = base64(entry.wrappedDekBase64)
        val aes = AESEncryptionEngine()
        val dek = aes.decrypt(wrapped.copyOfRange(CryptoConstants.GCM_IV_SIZE, wrapped.size), keys.key(entry.keyEpoch), wrapped.copyOfRange(0, CryptoConstants.GCM_IV_SIZE))
        val iv = base64(entry.ivBase64)
        val partial = File(target.parentFile, target.name + ".partial")
        try {
            val digest = MessageDigest.getInstance("SHA-256")
            BufferedInputStream(FileInputStream(blob)).use { input ->
                DigestOutputStream(BufferedOutputStream(FileOutputStream(partial)), digest).use { out ->
                    aes.decryptChunked(input, out, dek, iv, CryptoConstants.PLAIN_CHUNK_SIZE, entry.encryptionVersion)
                }
            }
            check(SecurityUtils.toHex(digest.digest()).concatToString() == entry.checksum) { "${entry.name} does not match its checksum" }
            check(partial.renameTo(target)) { "Could not move ${entry.name} into place" }
        } catch (e: Exception) {
            partial.delete()
            throw e
        } finally {
            SecurityUtils.fillZero(dek)
        }
    }

    // --- Internals ------------------------------------------------------------------------------------------------------

    private fun openBatch(file: File, manifest: Manifest, keys: ShareKeys, writers: Map<String, Member>): Batch? {
        val envelope = json.decodeFromString(Envelope.serializer(), file.readText())
        if (envelope.format != "SINO-SHARE-BATCH" || envelope.version != 1 || envelope.shareId != manifest.shareId) return null
        val member = writers[envelope.writer.substringBefore('/')] ?: return null
        val unsigned = json.encodeToString(Envelope.serializer(), envelope.copy(signatureBase64 = null)).encodeToByteArray()
        val signature = envelope.signatureBase64?.let(::base64) ?: return null
        if (!MLDSAEngine().verify(unsigned, signature, base64(member.signerBase64))) return null
        // The batch must sit at its writer's name, so one cannot stand in for another.
        val expected = cloudName(keys, "share-batch:${envelope.writer}") + ".batch"
        if (file.name != expected || envelope.epoch !in 1..keys.epoch) return null
        val sealed = base64(envelope.sealedBase64)
        val key = keys.domainKey(envelope.epoch, "SINO/V1/SHARE-BATCH")
        val plain = try {
            AESEncryptionEngine().decrypt(sealed.copyOfRange(CryptoConstants.GCM_IV_SIZE, sealed.size), key, sealed.copyOfRange(0, CryptoConstants.GCM_IV_SIZE))
        } finally {
            SecurityUtils.fillZero(key)
        }
        val batch = json.decodeFromString(Batch.serializer(), plain.decodeToString())
        SecurityUtils.fillZero(plain)
        return batch.takeIf { it.shareId == envelope.shareId && it.writer == envelope.writer && it.sequence == envelope.sequence }
    }

    private fun openName(manifest: Manifest, keys: ShareKeys): String {
        val sealed = base64(manifest.nameBase64)
        val key = keys.domainKey(manifest.epoch, "SINO/V1/SHARE-NAME")
        return try {
            AESEncryptionEngine().decrypt(sealed.copyOfRange(CryptoConstants.GCM_IV_SIZE, sealed.size), key, sealed.copyOfRange(0, CryptoConstants.GCM_IV_SIZE)).decodeToString()
        } finally {
            SecurityUtils.fillZero(key)
        }
    }

    private fun bundle(manifest: Manifest, plain: ByteArray): ShareKeys {
        try {
            val bundle = json.decodeFromString(KeyBundle.serializer(), plain.decodeToString())
            require(bundle.shareId == manifest.shareId && bundle.epoch == manifest.epoch && bundle.keysBase64.size == bundle.epoch) { "The folder's keys are for another folder or epoch" }
            return ShareKeys(bundle.shareId, base64(bundle.saltBase64), bundle.keysBase64.map(::base64))
        } finally {
            SecurityUtils.fillZero(plain)
        }
    }

    /**
     * The hybrid container (`SINO ‖ 3 ‖ u16 rsaCtLength ‖ rsaCt ‖ kemCt(1088) ‖ iv(12) ‖ gcm`), opened under
     * `HKDF-SHA-512(kemSecret ‖ rsaSecret, domain + hex(SHA-256(kemCt ‖ rsaCt ‖ rsaSpki ‖ kemPublicKey)), 32)`.
     */
    private fun openHybrid(container: ByteArray, domain: String, rsaPkcs8: ByteArray, rsaSpki: ByteArray, kemPrivate: ByteArray, kemPublic: ByteArray): ByteArray {
        val buffer = ByteBuffer.wrap(container)
        require(container.size > 7 + MLKEMEngine.CIPHERTEXT_SIZE + 28) { "The sealed keys are truncated" }
        val magic = ByteArray(4).also { buffer.get(it) }
        require(magic.contentEquals("SINO".encodeToByteArray()) && buffer.get().toInt() == 3) { "Unknown sealed-key container" }
        val rsaLength = buffer.short.toInt() and 0xFFFF
        require(rsaLength > 0 && buffer.remaining() > rsaLength + MLKEMEngine.CIPHERTEXT_SIZE + 28) { "The sealed keys are truncated" }
        val rsaCt = ByteArray(rsaLength).also { buffer.get(it) }
        val kemCt = ByteArray(MLKEMEngine.CIPHERTEXT_SIZE).also { buffer.get(it) }
        val iv = ByteArray(CryptoConstants.GCM_IV_SIZE).also { buffer.get(it) }
        val sealed = ByteArray(buffer.remaining()).also { buffer.get(it) }
        var kemSecret: ByteArray? = null
        var rsaSecret: ByteArray? = null
        var ikm: ByteArray? = null
        var kek: ByteArray? = null
        try {
            kemSecret = MLKEMEngine().decapsulate(kemCt, kemPrivate)
            rsaSecret = OrganisationRecovery.rsaDecrypt(rsaCt, rsaPkcs8)
            require(rsaSecret.size == 32) { "The folder's keys do not open" }
            val transcript = MessageDigest.getInstance("SHA-256").digest(kemCt + rsaCt + rsaSpki + kemPublic)
            ikm = kemSecret + rsaSecret
            kek = HKDFEngine().derive(ikm, domain + SecurityUtils.toHex(transcript).concatToString(), CryptoConstants.AES_KEY_SIZE)
            return try {
                AESEncryptionEngine().decrypt(sealed, kek, iv)
            } catch (e: Exception) {
                throw IllegalArgumentException("The folder's keys do not open: they were changed, or sealed for someone else")
            }
        } catch (e: IllegalArgumentException) {
            throw e
        } catch (e: Exception) {
            throw IllegalArgumentException("The folder's keys do not open")
        } finally {
            SecurityUtils.fillZero(kemSecret)
            SecurityUtils.fillZero(rsaSecret)
            SecurityUtils.fillZero(ikm)
            SecurityUtils.fillZero(kek)
        }
    }

    /** HMAC-SHA256(salt, label), first 16 bytes in lower-case hex: names in the folder's storage. */
    private fun cloudName(keys: ShareKeys, label: String): String =
        javax.crypto.Mac.getInstance("HmacSHA256").run {
            init(javax.crypto.spec.SecretKeySpec(keys.salt, "HmacSHA256"))
            doFinal(label.encodeToByteArray())
        }.copyOf(16).joinToString("") { "%02x".format(it) }

    private fun dominates(a: Map<String, Long>, b: Map<String, Long>): Boolean {
        var more = false
        for (k in a.keys + b.keys) {
            val x = a[k] ?: 0
            val y = b[k] ?: 0
            if (x < y) return false
            if (x > y) more = true
        }
        return more
    }

    /** "report (conflict, <author>, 2026-10-19).pdf", as Sino names the later side of a conflict. */
    private fun conflictName(entry: Entry): String {
        val dot = entry.name.lastIndexOf('.').takeIf { it > 0 } ?: entry.name.length
        val date = Instant.ofEpochMilli(entry.modifiedAt).atZone(ZoneOffset.UTC).toLocalDate()
        return entry.name.substring(0, dot) + " (conflict, " + entry.author + ", " + date + ")" + entry.name.substring(dot)
    }

    private fun isSafeName(name: String): Boolean =
        name.isNotEmpty() && name != "." && name != ".." && name.length <= 255 && name.none { it == '/' || it == '\\' || it == ':' || it.isISOControl() }

    private fun base64(text: String): ByteArray = SecurityUtils.fromBase64(text.toCharArray())
}
