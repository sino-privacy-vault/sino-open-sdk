package com.sino.sdk.vault

import com.sino.sdk.crypto.SecurityUtils
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Sino's cloud layout. Each provider holds a `SinoVault` folder with:
 * - `security/`: `rmk_backup.bin`, `vault_salt.public` and `vault_manifest.json` (real vault only);
 * - `metadata/<namespace>/[<folder dir>/]<batch name>.batch`: one encrypted metadata batch per logical folder;
 * - `blobs/<namespace>/[<folder dir>/]<cloud name>.enc`: the encrypted files.
 *
 * Every name is an HMAC-SHA256 of the vault salt, truncated to hex: the namespace (16 characters) of
 * `"sino-vault-root:" + type`, a folder directory (32) of the folder's logical path (e.g. `DCIM/Camera`, none for
 * the root folder), and a batch name (16) of `"folder_metadata:" + path`. The real and decoy vaults use different
 * salts, so their namespaces look alike and cannot be linked.
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

    /** The directory of a logical folder inside a namespace; empty for the root folder. */
    fun folderDirName(salt: ByteArray, relativePath: String): String =
        if (relativePath.isEmpty()) "" else hmacHex(salt, relativePath, FOLDER_NAME_LENGTH)

    fun batchFileName(salt: ByteArray, relativePath: String): String =
        hmacHex(salt, BATCH_NAME_LABEL + relativePath, NAME_LENGTH) + BATCH_EXTENSION

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
