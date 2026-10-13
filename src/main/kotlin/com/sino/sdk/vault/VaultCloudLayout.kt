package com.sino.sdk.vault

import com.sino.sdk.crypto.SecurityUtils
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Sino's cloud layout. Each provider holds a `SinoVault` folder with:
 * - `security/`: `rmk_backup.bin`, `vault_salt.public` and `vault_manifest.json` (real vault only);
 * - `metadata/<namespace>/[<folder key>/]<batch name>.batch`: one encrypted metadata batch per folder;
 * - `blobs/<namespace>/[<folder key>/]<cloud name>.enc`: the encrypted files.
 *
 * Every name is an HMAC-SHA256 of the vault salt, truncated to hex: the namespace (16 characters) of
 * `"sino-vault-root:" + type`, and a batch name (16) of `"folder_metadata:" + folder key`. A folder's key (32, none for
 * the root folder) is recorded in its batch: Sino derives it from the folder's logical path (e.g. `DCIM/Camera`) when
 * the folder first reaches the clouds and keeps it when the folder is renamed or moved, so a reader takes it from the
 * batch. The real and decoy vaults use different salts, so their namespaces look alike and cannot be linked.
 */
object VaultCloudLayout {
    const val VAULT_FOLDER = "SinoVault"
    const val BLOBS = "blobs"
    const val METADATA = "metadata"
    const val SECURITY = "security"
    const val RMK_BACKUP_FILE = "rmk_backup.bin"
    const val PUBLIC_SALT_FILE = "vault_salt.public"
    const val MANIFEST_FILE = "vault_manifest.json"
    const val BATCH_EXTENSION = ".batch"
    const val BLOB_EXTENSION = ".enc"

    private const val ROOT_DOMAIN = "sino-vault-root:"
    private const val BATCH_NAME_LABEL = "folder_metadata:"
    private const val NAME_LENGTH = 16
    private const val FOLDER_NAME_LENGTH = 32

    /** The namespace directory of [type] ([BLOBS] or [METADATA]) for the vault owning [salt]. */
    fun namespace(salt: ByteArray, type: String): String = hmacHex(salt, ROOT_DOMAIN + type, NAME_LENGTH)

    /**
     * The key Sino gives a folder at [relativePath] when it first reaches the clouds (its directory inside a namespace);
     * empty for the root folder. A renamed or moved folder keeps its first key. Used to build test vaults.
     */
    fun folderKey(salt: ByteArray, relativePath: String): String =
        if (relativePath.isEmpty()) "" else hmacHex(salt, relativePath, FOLDER_NAME_LENGTH)

    /** Whether [key] can name a folder directory: 32 lower-case hex characters ("" is the root folder). */
    fun isFolderKey(key: String): Boolean = key.length == FOLDER_NAME_LENGTH && key.all { it in '0'..'9' || it in 'a'..'f' }

    fun batchFileName(salt: ByteArray, folderKey: String): String =
        hmacHex(salt, BATCH_NAME_LABEL + folderKey, NAME_LENGTH) + BATCH_EXTENSION

    private fun hmacHex(salt: ByteArray, label: String, length: Int): String {
        require(salt.isNotEmpty()) { "Vault salt is missing" }
        val mac = Mac.getInstance("HmacSHA256").run {
            init(SecretKeySpec(salt, "HmacSHA256"))
            doFinal(label.encodeToByteArray())
        }
        val hex = SecurityUtils.toHex(mac)
        return try {
            hex.concatToString(0, minOf(length, hex.size))
        } finally {
            SecurityUtils.fillZero(hex)
        }
    }
}
