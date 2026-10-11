# Sino Cryptographic Specification

This is the open specification of the data Sino stores in your cloud accounts. Everything here is implemented by
this SDK, which reads and verifies that data without the Sino apps (`com.sino.sdk.vault`). The SDK's tests recover a
vault written by Sino's own code, so this document and the apps cannot silently drift apart.

Notation: `||` is concatenation, `HMAC-SHA256(k, m)`, `HKDF(ikm, info)` is HKDF-SHA-512 (RFC 5869) without a salt,
and `AES-GCM(k, iv, m)` is AES-256-GCM with a 96-bit nonce and a 128-bit tag appended to the ciphertext.

---

## 1. Keys

```
recovery phrase (24 words)                       vault root key (RMK, 32 random bytes)
        │ Argon2id(recovery salt)                        │
        ▼                                                ├─ domain keys: HMAC-SHA256(RMK, domain || 0x01)
   phrase root ── HKDF "SINO/V1/RECOVERY-KEK" ──▶ KEK    │    ├─ "FolderMetadataBatchV1"        metadata batch key
                                                  │      │    ├─ "SINO/V1/VAULT-MANIFEST-SIGNER" ML-DSA-65 seed
        rmk_backup.bin = container(RMK || vault salt)    │    └─ "SINO/V1/VAULT-MANIFEST-ID"     vault identifier
                                                         └─ wraps each file's random DEK: iv(12) || AES-GCM(RMK, iv, DEK)
```

- The **RMK** is generated once per vault. On a device it is released by the master password or a biometric-gated
  hardware key and is wiped from memory on lock; those device-local wrappers are not needed for recovery.
- **File keys (DEKs)** are 32 random bytes per file, never derived from file ids. A wrapped DEK is stored as
  `base64(iv || AES-GCM(RMK, iv, DEK))`.
- The **vault salt** (at least 16 random bytes) keys the vault's cloud names (§5). It leaves the device only inside
  the encrypted recovery backup.

## 2. File encryption (chunked AES-GCM, format 2)

- The (optionally gzip-compressed) file is split into 1 MiB (1,048,576-byte) chunks; the last may be shorter.
- Chunk `i` is `AES-GCM(DEK, nonce_i, chunk)`, so each stored chunk is 16 bytes longer. `nonce_i` is the file's random
  12-byte base nonce with bytes 8..11 replaced by `i` as a big-endian 32-bit integer (at most 2^32 chunks).
- Chunks are concatenated with no header. Reordering, truncating inside a chunk or modifying any byte fails
  authentication.
- Before encryption, images and videos may be stripped of metadata and videos transcoded, and some files are
  gzip-compressed. The batch entry records `cloudChecksum`, the SHA-256 of exactly the bytes that were encrypted,
  and `isCompressed`. Recovery checks the checksum and then decompresses.

## 3. Artifact container (version 2)

Metadata batches and the recovery backup use one container:

`"SINO" || 0x02 || iv(12) || AES-GCM(key, iv, data) || SHA-256(all preceding bytes)`

AES-GCM provides confidentiality and authenticity. The unkeyed SHA-256 only distinguishes storage corruption from
a wrong key or tampering. Each artifact type uses its own key.

## 4. Recovery backup

`SinoVault/security/` holds:

- `vault_salt.public`: the **recovery salt** `HKDF(vault salt, "SINO/V1/RECOVERY-SALT")`, 32 bytes. It is one-way,
  so publishing it reveals nothing about the vault salt.
- `rmk_backup.bin`: a container (§3) under the KEK, holding `RMK(32) || vault salt`.

The KEK is `HKDF(Argon2id(phrase, recovery salt), "SINO/V1/RECOVERY-KEK")`, with Argon2id version 1.3, 64 MiB,
3 iterations, 4 lanes and a 32-byte output. The phrase is normalised first: each word is trimmed and lower-cased,
and the words are joined by single spaces. The apps also store a verifier `HKDF(root, "SINO/V1/RECOVERY-VERIFIER")`
on the device, which cannot open the backup.

## 5. Cloud layout

Each provider holds a `SinoVault` folder:

```
SinoVault/
  security/   rmk_backup.bin, vault_salt.public, vault_manifest.json
  metadata/<namespace>/<batch>.batch                    batch of the root folder
  metadata/<namespace>/<folder dir>/<batch>.batch       batch of the folder "DCIM/Camera", ...
  blobs/<namespace>/[<folder dir>/]<cloud name>.enc     encrypted files (§2)
```

All names are lower-case hex of `HMAC-SHA256(vault salt, label)`, truncated as follows:

| Name | Label | Length |
| --- | --- | --- |
| namespace | `"sino-vault-root:" + "metadata"` or `"…blobs"` | 16 |
| folder dir | the folder's logical path, e.g. `DCIM/Camera` (none for the root folder) | 32 |
| batch | `"folder_metadata:" + logical path`, plus `.batch` | 16 |

Every device derives the same names from the same paths. Cloud names of files are opaque and recorded in the
batches. The real and decoy vaults have different salts, so their namespaces look alike and cannot be linked.

## 6. Folder metadata batches

A batch is `container(batch key, gzip(JSON))` (§3) of:

```json
{ "folderPath": "DCIM/Camera", "version": 6, "lastUpdated": 0,
  "files":   { "<file name>": <entry> },
  "deleted": { "<file name>": { "version": 2, "checksum": "...", "deletedAt": 0 } },
  "acks":    { "<device id>": { "version": 6, "at": 0 } } }
```

Each entry carries `originalName`, `relativePath` (the folder), `mimeType`, `size`, `checksum` (SHA-256 of the file
as added), `encryptedDEK` (§1), `iv` (base64 base nonce), `encryptionVersion` (2), `isChunked` (true),
`isCompressed`, `cloudChecksum` (§2), `cloudName`, `isTrashed`, `isDuress` (false in the real vault), `timestamp`
and `providerHints`. Unknown fields are ignored.

- **Placement:** all batches share one key, so a reader must check that the decrypted `folderPath` maps to the
  directory and batch name it was found under (§5), and must discard batches that do not.
- **Merge across providers:** sort the copies by `version`. Take the union of the entries, with higher versions
  winning name conflicts. Keep the newest tombstone per name. An entry survives a tombstone only if a batch newer
  than the tombstone lists it.

## 7. Device list (`security/vault_manifest.json`)

```json
{ "format": "SINO-VAULT", "version": 1, "cryptoSuite": "SINO-VAULT-V1-AES256GCM-HKDFSHA512-MLKEM768-MLDSA65",
  "keyEpoch": 4, "vaultIdentifier": "<32 hex>", "keyEnvelopes": [ <envelope> ], "revokedKeyIds": [ "device-…" ],
  "mldsaSignatureBase64": "…", "signerKeyId": "device-…", "createdAt": 0 }
```

- **Signature:** ML-DSA-65 (pure, empty context) over the JSON of the manifest with `mldsaSignatureBase64` set to
  null. Every field is written, defaults included, in the order above. The signing key pair is
  `ML-DSA.KeyGen_internal(ξ = domain key "SINO/V1/VAULT-MANIFEST-SIGNER")`, so every unlocked device can sign and
  anyone holding the RMK can verify. `vaultIdentifier` is the hex of the first 16 bytes of the domain key
  `"SINO/V1/VAULT-MANIFEST-ID"`.
- **Envelopes:** each enrolled device has an ML-KEM-768 key pair from a 64-byte `d || z` seed that never leaves the
  device. Its envelope seals the RMK as `AES-GCM(HKDF(sharedSecret, "SINO/V1/DEVICE-ENVELOPE|<suite>|<device id>"),
  nonce, RMK)`. The tag is part of `ciphertextBase64`, `authTagBase64` is empty, and `pqcEncapsulationBase64` is the
  ML-KEM ciphertext. Binding the device id and suite stops an envelope from being replayed into another slot.
- **Revocation:** a revoked device moves from `keyEnvelopes` to `revokedKeyIds`, the epoch increases and the list is
  re-signed. Each device pins the signer key and the newest epoch it accepted. It wipes itself (that device only)
  when a list that verifies names it in `revokedKeyIds`. Being missing from the envelopes is not a revocation.
  Revocation is a kill switch for a lost device, not a cryptographic lock-out: every device has held the RMK.

## 8. Post-quantum parameters

| Algorithm | Standard | Public key | Private key | Ciphertext / signature |
| --- | --- | --- | --- | --- |
| ML-KEM-768 | FIPS 203 | 1,184 | 2,400 (or 64-byte seed) | 1,088; shared secret 32 |
| ML-DSA-65 | FIPS 204 | 1,952 | 4,032 (or 32-byte seed) | 3,309 |

Sino ships its own pure-Kotlin implementations, validated against the NIST ACVP vectors. This SDK uses
BouncyCastle, an independent implementation, so verifying a manifest with the SDK also cross-checks Sino's.

## 9. The decoy (duress) vault

The decoy vault has its own salt, its own namespaces and its own root key. That root key is
`HMAC-SHA256(device key, "SINO/V1/DECOY-ROOT" || 0x01)`, derived from a hardware-sealed key of one device. It has
no recovery phrase and no backup, and nothing in the real vault's data refers to it. Without that device it cannot
be decrypted, by design. A recovery with the real vault's phrase never reads it.

## 10. Memory hygiene

Keys, phrases and plaintext buffers are held in byte or char arrays and zeroed after use. Text decoders are strict,
and their errors never echo input characters, which may be secret.

## 11. Recovery without the apps

```bash
./gradlew recoveryJar
java -jar build/libs/sino-recovery-<version>.jar recover --vault <SinoVault copy> [--vault <another provider's copy>] --out <folder>
```

See the README for every command. Recovery is offline and never overwrites existing files. Each file is checked
against `cloudChecksum`. A damaged copy is replaced by another provider's copy.
