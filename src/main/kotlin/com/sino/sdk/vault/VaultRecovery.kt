package com.sino.sdk.vault

import com.sino.sdk.crypto.AESEncryptionEngine
import com.sino.sdk.crypto.CryptoConstants
import com.sino.sdk.crypto.DeviceInfo
import com.sino.sdk.crypto.KeyEnvelope
import com.sino.sdk.crypto.SecurityUtils
import com.sino.sdk.crypto.VaultManifest
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.DigestOutputStream
import java.security.MessageDigest
import java.util.zip.GZIPInputStream

/**
 * Offline recovery of a Sino vault from copies of its cloud folders, with nothing but the recovery phrase.
 *
 * Download the `SinoVault` folder from each provider you used (MEGA, Google Drive, S3), then point [open] at those
 * folders (or at folders containing them). Every copy is used: batches of one folder are merged across providers the
 * way Sino merges them, and a file whose copy on one provider is missing or damaged is read from another.
 *
 * Only the real vault can be recovered (see [VaultKeys]); the decoy vault's data is never read.
 */
class VaultRecovery private constructor(
    private val roots: List<Root>,
    private val keys: VaultKeys,
    private val vaultSalt: ByteArray,
) : AutoCloseable {

    /** One provider's copy of the `SinoVault` folder; [label] names it in reports (the path the user gave). */
    class Root(val label: String, val dir: File)

    /** A file of the vault, with every provider copy of its ciphertext. */
    class VaultFile(val folderPath: String, val name: String, val entry: MediaMetadata, val copies: List<File>) {
        val path: String get() = if (folderPath.isEmpty()) name else "$folderPath/$name"
    }

    class Problem(val path: String?, val message: String) {
        override fun toString() = if (path == null) message else "$path: $message"
    }

    class Index(val files: List<VaultFile>, val problems: List<Problem>)

    class RecoveryReport(val recovered: List<String>, val failed: List<Problem>, val skipped: List<Problem>)

    class ManifestReport(
        /** The newest manifest that verifies, or null if none does. */
        val manifest: VaultManifest?,
        /** Manifests that were found but do not verify (tampered, replayed or from another vault). */
        val rejected: List<Problem>,
    )

    private val aes = AESEncryptionEngine()

    /** Reads, verifies and merges every metadata batch of the vault. Unreadable or misplaced batches are reported. */
    fun index(): Index {
        val problems = mutableListOf<Problem>()
        val byFolder = mutableMapOf<String, MutableList<FolderMetadataBatch>>()
        val batchKey = keys.metadataBatchKey()
        try {
            for (root in roots) {
                val ns = File(root.dir, "${VaultCloudLayout.METADATA}/${VaultCloudLayout.namespace(vaultSalt, VaultCloudLayout.METADATA)}")
                if (!ns.isDirectory) {
                    problems += Problem(null, "${root.label}: no metadata for this vault")
                    continue
                }
                val candidates = ns.listFiles().orEmpty().flatMap { child ->
                    when {
                        child.isFile -> listOf("" to child)
                        child.isDirectory -> child.listFiles().orEmpty().filter { it.isFile }.map { child.name to it }
                        else -> emptyList()
                    }
                }.filter { it.second.name.endsWith(VaultCloudLayout.BATCH_EXTENSION) }

                for ((dirName, file) in candidates) {
                    val where = "${root.label}: ${file.relativeTo(root.dir).invariantSeparatorsPath}"
                    val batch = try {
                        FolderMetadataBatchCodec.decode(file.readBytes(), batchKey)
                    } catch (e: Exception) {
                        problems += Problem(null, "$where: unreadable metadata batch (${e.javaClass.simpleName})")
                        continue
                    }
                    if (!FolderMetadataBatchCodec.isPlacedAt(vaultSalt, batch, dirName, file.name)) {
                        problems += Problem(null, "$where: metadata batch is not where its folder belongs; ignored")
                        continue
                    }
                    byFolder.getOrPut(batch.folderKey) { mutableListOf() } += batch
                }
            }
        } finally {
            SecurityUtils.fillZero(batchKey)
        }

        val blobNs = VaultCloudLayout.namespace(vaultSalt, VaultCloudLayout.BLOBS)
        // By folder key: a folder keeps its key (and directory) when it is renamed or moved; its path is the newest.
        val files = byFolder.values.mapNotNull { FolderMetadataBatchCodec.merge(it) }.sortedBy { it.folderPath }.flatMap { merged ->
            val folderPath = merged.folderPath
            val dir = merged.folderKey
            merged.files.toSortedMap().mapNotNull { (name, entry) ->
                val path = if (folderPath.isEmpty()) name else "$folderPath/$name"
                if (entry.isDuress) {
                    problems += Problem(path, "entry belongs to the other vault; ignored")
                    return@mapNotNull null
                }
                val cloudName = entry.cloudName
                if (cloudName.isNullOrEmpty() || !isSafeName(cloudName)) {
                    problems += Problem(path, "entry has no valid cloud name")
                    return@mapNotNull null
                }
                val relative = listOf(VaultCloudLayout.BLOBS, blobNs, dir, cloudName + VaultCloudLayout.BLOB_EXTENSION).filter { it.isNotEmpty() }.joinToString("/")
                VaultFile(folderPath, name, entry, roots.map { File(it.dir, relative) }.filter { it.isFile })
            }
        }
        return Index(files, problems)
    }

    /**
     * Decrypts the vault's files into [outputDir] at their original paths (`<folder>/<name>`). Existing files are never
     * overwritten. Each file is checked against the checksum recorded when it was encrypted; a damaged copy is
     * discarded and the next provider's copy is tried. Trashed files are skipped unless [includeTrashed].
     */
    fun recover(outputDir: File, includeTrashed: Boolean = false, onFile: (String) -> Unit = {}): RecoveryReport {
        val index = index()
        val recovered = mutableListOf<String>()
        val failed = mutableListOf<Problem>()
        val skipped = index.problems.toMutableList()
        outputDir.mkdirs()
        val base = outputDir.canonicalFile

        for (file in index.files) {
            if (file.entry.isTrashed && !includeTrashed) {
                skipped += Problem(file.path, "in the trash (use --include-trashed)")
                continue
            }
            val target = safeTarget(base, file)
            if (target == null) {
                failed += Problem(file.path, "unsafe file path; not written")
                continue
            }
            if (target.exists()) {
                skipped += Problem(file.path, "already exists in the output folder; not overwritten")
                continue
            }
            if (file.copies.isEmpty()) {
                failed += Problem(file.path, "no provider copy of its encrypted data was found")
                continue
            }
            onFile(file.path)
            val errors = mutableListOf<String>()
            val ok = file.copies.any { copy ->
                try {
                    decryptTo(file.entry, copy, target)
                    true
                } catch (e: Exception) {
                    errors += e.message ?: e.javaClass.simpleName
                    false
                }
            }
            if (ok) {
                target.setLastModified(file.entry.timestamp)
                recovered += file.path
            } else {
                failed += Problem(file.path, errors.distinct().joinToString("; "))
            }
        }
        return RecoveryReport(recovered, failed, skipped)
    }

    /** The name and type of an enrolled device, or null if [envelope] has none this vault can open. */
    fun deviceInfo(envelope: KeyEnvelope): DeviceInfo? = keys.openDeviceInfo(envelope)

    /** Reads `security/vault_manifest.json` from every copy and returns the newest one signed by this vault. */
    fun verifyManifest(): ManifestReport {
        val verifier = ManifestVerifier.forVault(keys)
        val rejected = mutableListOf<Problem>()
        val trusted = roots.mapNotNull { root ->
            val file = File(root.dir, "${VaultCloudLayout.SECURITY}/${VaultCloudLayout.MANIFEST_FILE}")
            if (!file.isFile) return@mapNotNull null
            val manifest = try {
                VaultManifest.fromJson(file.readText(Charsets.UTF_8))
            } catch (e: Exception) {
                rejected += Problem(null, "${root.label}: device list is not valid JSON")
                return@mapNotNull null
            }
            if (verifier.verifies(manifest)) manifest else {
                rejected += Problem(null, "${root.label}: device list does not verify against this vault's signing key")
                null
            }
        }
        return ManifestReport(trusted.maxByOrNull { it.keyEpoch }, rejected)
    }

    /** Decrypts one copy to [target] via a partial file; nothing is left behind on failure. */
    private fun decryptTo(entry: MediaMetadata, blob: File, target: File) {
        require(entry.isChunked && entry.encryptionVersion == CryptoConstants.CHUNK_FORMAT_VERSION) {
            "unsupported encryption format (chunked=${entry.isChunked}, version=${entry.encryptionVersion})"
        }
        target.parentFile.mkdirs()
        val partial = File(target.parentFile, target.name + PARTIAL_SUFFIX)
        val staged = File(target.parentFile, target.name + STAGED_SUFFIX)
        val dek = keys.unwrapDek(entry.encryptedDEK)
        val ivChars = entry.iv.toCharArray()
        val iv = try {
            SecurityUtils.fromBase64(ivChars)
        } finally {
            SecurityUtils.fillZero(ivChars)
        }
        try {
            val encryptedTo = if (entry.isCompressed) staged else partial
            val digest = MessageDigest.getInstance("SHA-256")
            BufferedInputStream(FileInputStream(blob)).use { input ->
                DigestOutputStream(BufferedOutputStream(FileOutputStream(encryptedTo)), digest).use { out ->
                    try {
                        aes.decryptChunked(input, out, dek, iv)
                    } catch (e: javax.crypto.AEADBadTagException) {
                        throw IllegalStateException("damaged or tampered copy (authentication failed)")
                    }
                }
            }
            val actual = SecurityUtils.toHex(digest.digest()).concatToString()
            val expected = entry.cloudChecksum
            if (expected != null && !expected.equals(actual, ignoreCase = true)) {
                throw IllegalStateException("decrypted data does not match its recorded checksum")
            }
            if (entry.isCompressed) {
                GZIPInputStream(BufferedInputStream(FileInputStream(staged))).use { gz ->
                    BufferedOutputStream(FileOutputStream(partial)).use { out -> gz.copyTo(out) }
                }
            }
            if (!partial.renameTo(target)) throw IllegalStateException("could not move the recovered file into place")
        } catch (e: Exception) {
            partial.delete()
            throw e
        } finally {
            staged.delete()
            SecurityUtils.fillZero(dek)
            SecurityUtils.fillZero(iv)
        }
    }

    /** `<base>/<folder>/<name>`, or null if any component could escape [base] or is not a plain name. */
    private fun safeTarget(base: File, file: VaultFile): File? {
        val parts = (if (file.folderPath.isEmpty()) emptyList() else file.folderPath.split('/')) + file.name
        if (parts.any { !isSafeName(it) }) return null
        val target = File(base, parts.joinToString(File.separator)).canonicalFile
        return target.takeIf { it.toPath().startsWith(base.toPath()) && it != base }
    }

    private fun isSafeName(name: String): Boolean =
        name.isNotEmpty() && name != "." && name != ".." && name.length <= 255 &&
            name.none { it == '/' || it == '\\' || it == ':' || it == '\u0000' || it.isISOControl() } &&
            !name.endsWith(PARTIAL_SUFFIX) && !name.endsWith(STAGED_SUFFIX)

    override fun close() {
        keys.close()
        SecurityUtils.fillZero(vaultSalt)
    }

    companion object {
        private const val PARTIAL_SUFFIX = ".sino-partial"
        private const val STAGED_SUFFIX = ".sino-staged"

        /**
         * Finds the `SinoVault` folder in each of [dirs] (the folder itself, or a folder containing it), opens the
         * recovery backup with [phrase] and returns the opened vault. Throws [IllegalArgumentException] if no backup
         * opens with the phrase, [IllegalStateException] if no backup is found.
         */
        fun open(dirs: List<File>, phrase: List<CharArray>, kit: RecoveryKit = RecoveryKit()): VaultRecovery {
            val roots = rootsOf(dirs)
            val backups = roots.mapNotNull { root ->
                val security = File(root.dir, VaultCloudLayout.SECURITY)
                val salt = File(security, VaultCloudLayout.PUBLIC_SALT_FILE).takeIf { it.isFile }?.readBytes()
                val backup = File(security, VaultCloudLayout.RMK_BACKUP_FILE).takeIf { it.isFile }?.readBytes()
                if (salt != null && backup != null && salt.isNotEmpty() && backup.isNotEmpty()) salt to backup else null
            }
            if (backups.isEmpty()) {
                throw IllegalStateException("No recovery backup (security/${VaultCloudLayout.RMK_BACKUP_FILE} and ${VaultCloudLayout.PUBLIC_SALT_FILE}) was found")
            }
            // Argon2id is slow: stretch the phrase once per distinct salt.
            for ((salt, group) in backups.groupBy { it.first.toList() }) {
                val kek = kit.deriveKek(phrase, salt.toByteArray())
                try {
                    for ((_, backup) in group) {
                        val vault = try {
                            kit.openBackup(backup, kek)
                        } catch (e: IllegalArgumentException) {
                            continue
                        }
                        vault.use { return VaultRecovery(roots, VaultKeys(it.rootKey), it.vaultSalt.copyOf()) }
                    }
                } finally {
                    SecurityUtils.fillZero(kek)
                }
            }
            throw IllegalArgumentException("The recovery phrase does not match this vault's backup")
        }

        /**
         * Opens the vault in [dirs] with its root key and salt when they come from elsewhere than the recovery phrase:
         * a managed vault's recovery file opened with the organisation's kits ([com.sino.sdk.org.OrganisationRecovery]).
         * Copies both; the caller wipes its own.
         */
        fun openWithKeys(dirs: List<File>, rootKey: ByteArray, vaultSalt: ByteArray): VaultRecovery {
            require(rootKey.size == CryptoConstants.AES_KEY_SIZE && vaultSalt.size >= 16) { "Not a vault key and salt" }
            return VaultRecovery(rootsOf(dirs), VaultKeys(rootKey), vaultSalt.copyOf())
        }

        private fun rootsOf(dirs: List<File>): List<Root> = dirs.map { dir ->
            val nested = File(dir, VaultCloudLayout.VAULT_FOLDER)
            Root(dir.path, if (nested.isDirectory) nested else dir)
        }
    }
}
