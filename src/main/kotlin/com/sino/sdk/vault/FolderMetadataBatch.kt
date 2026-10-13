package com.sino.sdk.vault

import com.sino.sdk.crypto.CryptoConstants
import com.sino.sdk.crypto.SecurityUtils
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream

/** One folder's file list, as every device of the vault publishes it. */
@Serializable
data class FolderMetadataBatch(
    /** The folder's path now (it can change; [folderKey] does not). */
    val folderPath: String,
    /** File name -> entry. */
    val files: Map<String, MediaMetadata>,
    val version: Long = 0,
    val lastUpdated: Long = 0,
    /** Tombstones of permanently deleted entries (file name -> tombstone). */
    val deleted: Map<String, FileTombstone> = emptyMap(),
    /** Per device: the newest batch version it published. */
    val acks: Map<String, DeviceAck> = emptyMap(),
    /** The folder's directory name; empty for the root folder only. */
    val folderKey: String = "",
    /** When [folderPath] was set (0: never changed); the newest path wins a merge. */
    val pathChangedAt: Long = 0,
    /** When the folder was deleted (0: it exists). */
    val removedAt: Long = 0,
)

@Serializable
data class FileTombstone(val version: Long, val checksum: String, val deletedAt: Long)

@Serializable
data class DeviceAck(val version: Long, val at: Long)

/** One file. Its ciphertext is `blobs/<namespace>/[<folder key>/]<cloudName>.enc`. */
@Serializable
data class MediaMetadata(
    val originalName: String,
    val relativePath: String,
    val mimeType: String,
    val size: Long,
    /** SHA-256 (hex) of the file as it was added (before any transcoding or metadata scrubbing). */
    val checksum: String,
    val megaFileId: String? = null,
    /** The file's random DEK, wrapped by the vault root key ([VaultKeys.unwrapDek]). */
    val encryptedDEK: String,
    /** Base64 of the 12-byte base nonce of the chunked encryption. */
    val iv: String,
    val encryptionVersion: Int = CryptoConstants.CHUNK_FORMAT_VERSION,
    val timestamp: Long,
    /** The encrypted bytes are gzip of the file. */
    val isCompressed: Boolean = false,
    val isChunked: Boolean = false,
    /** SHA-256 (hex) of exactly the bytes that were encrypted (after compression), checked on recovery. */
    val cloudChecksum: String? = null,
    val isDuress: Boolean = false,
    val providerHints: List<String> = emptyList(),
    val cloudName: String? = null,
    val isTrashed: Boolean = false,
)

/**
 * Sino's batch format: JSON -> gzip -> [ArtifactContainer] under the vault's batch key ([VaultKeys.metadataBatchKey]).
 */
object FolderMetadataBatchCodec {

    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }

    /** Verifies, decrypts and parses a batch; throws on tampering, a foreign key or bad data. */
    fun decode(payload: ByteArray, batchKey: ByteArray): FolderMetadataBatch {
        val compressed = ArtifactContainer.unwrap(payload, batchKey)
        var jsonBytes: ByteArray? = null
        var chars: CharArray? = null
        try {
            jsonBytes = GZIPInputStream(ByteArrayInputStream(compressed)).use { it.readBytes() }
            chars = SecurityUtils.fromUtf8(jsonBytes)
            return json.decodeFromString(FolderMetadataBatch.serializer(), chars.concatToString())
        } finally {
            SecurityUtils.fillZero(compressed)
            SecurityUtils.fillZero(jsonBytes)
            SecurityUtils.fillZero(chars)
        }
    }

    /** Encodes a batch the way Sino does. Used to build test vaults. */
    fun encode(batch: FolderMetadataBatch, batchKey: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        GZIPOutputStream(out).use { it.write(json.encodeToString(FolderMetadataBatch.serializer(), batch).encodeToByteArray()) }
        return ArtifactContainer.wrap(out.toByteArray(), batchKey)
    }

    /**
     * Whether [batch] was found where its own `folderKey` says it belongs. All batches of a vault share one key, so
     * a batch moved to another folder's location still decrypts; misplaced batches must be discarded. Only the root
     * folder has an empty key and an empty path.
     */
    fun isPlacedAt(salt: ByteArray, batch: FolderMetadataBatch, dirName: String, fileName: String): Boolean {
        val key = batch.folderKey
        val wellFormed = if (key.isEmpty()) batch.folderPath.isEmpty() else VaultCloudLayout.isFolderKey(key) && batch.folderPath.isNotEmpty()
        return wellFormed && key == dirName && VaultCloudLayout.batchFileName(salt, key) == fileName
    }

    /**
     * Sino's union merge of the copies of one folder's batch (one per provider): every entry of every copy is kept
     * (higher versions win name conflicts), and an entry deleted by a tombstone survives only if a batch newer than
     * the deletion lists it. The path with the newest `pathChangedAt` (then version) wins; `removedAt` is the newest
     * version's.
     */
    fun merge(batches: List<FolderMetadataBatch>): FolderMetadataBatch? {
        if (batches.isEmpty()) return null
        val ordered = batches.sortedBy { it.version }
        val merged = mutableMapOf<String, MediaMetadata>()
        val lastSeen = mutableMapOf<String, Long>()
        val tombstones = mutableMapOf<String, FileTombstone>()
        val acks = mutableMapOf<String, DeviceAck>()
        ordered.forEach { batch ->
            batch.files.forEach { (name, entry) ->
                val existing = merged[name]
                merged[name] = if (existing != null && existing.checksum == entry.checksum) {
                    entry.copy(providerHints = (existing.providerHints + entry.providerHints).distinct())
                } else {
                    entry
                }
                lastSeen[name] = batch.version
            }
            batch.deleted.forEach { (name, tombstone) ->
                val known = tombstones[name]
                if (known == null || tombstone.version > known.version) tombstones[name] = tombstone
            }
            batch.acks.forEach { (device, ack) ->
                val known = acks[device]
                acks[device] = if (known == null) ack else DeviceAck(maxOf(known.version, ack.version), maxOf(known.at, ack.at))
            }
        }
        val live = merged.filterKeys { name ->
            val tombstone = tombstones[name] ?: return@filterKeys true
            (lastSeen[name] ?: 0L) > tombstone.version
        }
        val newestPath = ordered.maxWith(compareBy<FolderMetadataBatch> { it.pathChangedAt }.thenBy { it.version })
        return ordered.last().copy(
            files = live, deleted = tombstones, acks = acks, lastUpdated = ordered.maxOf { it.lastUpdated },
            folderPath = newestPath.folderPath, pathChangedAt = newestPath.pathChangedAt,
        )
    }
}
