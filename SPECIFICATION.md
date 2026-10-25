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
  metadata/<namespace>/<folder key>/<batch>.batch       batch of a folder ("DCIM/Camera", ...)
  blobs/<namespace>/[<folder key>/]<cloud name>.enc     encrypted files (§2)
```

All names are lower-case hex of `HMAC-SHA256(vault salt, label)`, truncated as follows:

| Name | Label | Length |
| --- | --- | --- |
| namespace | `"sino-vault-root:" + "metadata"` or `"…blobs"` | 16 |
| folder key | the folder's logical path when it first reached the clouds, e.g. `DCIM/Camera` (none for the root folder) | 32 |
| batch | `"folder_metadata:" + folder key`, plus `.batch` | 16 |

Every device derives the same key from the same path, so a folder made on two devices meets in one place. A folder
keeps its key when it is renamed or moved (its batch records its path now), so a reader takes the key from the batch,
never from the path. Cloud names of files are opaque and recorded in the batches. The real and decoy vaults have
different salts, so their namespaces look alike and cannot be linked.

## 6. Folder metadata batches

A batch is `container(batch key, gzip(JSON))` (§3) of:

```json
{ "folderPath": "DCIM/Camera", "version": 6, "lastUpdated": 0,
  "files":   { "<file name>": <entry> },
  "deleted": { "<file name>": { "version": 2, "checksum": "...", "deletedAt": 0 } },
  "acks":    { "<device id>": { "version": 6, "at": 0 } },
  "folderKey": "<32 hex>", "pathChangedAt": 0, "removedAt": 0,
  "replaced": { "<cloud name>": { "checksum": "...", "replacedAt": 0 } } }
```

`folderKey` is the folder's directory (§5; empty for the root folder only). `pathChangedAt` is when `folderPath` was
last set by a rename or move (0: never). `removedAt` is when the folder was deleted (0: it exists); a deleted folder's
batch lists no live entries. `replaced` lists the blobs of versions an edit replaced; Sino deletes each one a week
after `replacedAt` once no entry names it. A reader can ignore it.

Each entry carries `originalName`, `relativePath` (the folder), `mimeType`, `size`, `checksum` (SHA-256 of the file
as added), `encryptedDEK` (§1), `iv` (base64 base nonce), `encryptionVersion` (2), `isChunked` (true),
`isCompressed`, `cloudChecksum` (§2), `cloudName`, `isTrashed`, `isDuress` (false in the real vault), `timestamp`,
`providerHints` and `lineage`: the earlier versions this one was edited from, newest first, each as the first 16
characters of its `checksum` (only versions that reached a cloud, at most 100). Unknown fields are ignored.

A name holds one version. When two devices edit one file apart (neither version is in the other's `lineage`), the
version published later is kept beside the other under a name of its own, `<name> (<device>, <yyyy-mm-dd>)<.ext>`.

- **Placement:** all batches share one key, so a reader must check that the decrypted `folderKey` is the directory
  and maps to the batch name it was found under (§5), that only the root folder's key and path are empty, and must
  discard batches that do not.
- **Merge across providers:** group the batches by `folderKey` and sort the copies by `version`. Take the union of
  the entries, with higher versions winning name conflicts, except that an entry whose `lineage` holds the other's
  checksum (an edit of it) always wins. Keep the newest tombstone per name. An entry survives a
  tombstone only if a batch newer than the tombstone lists it. The path is the one with the newest `pathChangedAt`
  (then version); `removedAt` is the highest version's.

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
- **Device entries** (`keyEnvelopes`, entry `version` 2): each enrolled device has a 64-byte `d || z` seed that never
  leaves the device. Its entry is `{ "version": 2, "cryptoSuite", "keyId": "<device id>", "deviceInfoBase64",
  "kemPublicKeyBase64", "signingPublicKeyBase64", "createdAt" }`: the public halves of its ML-KEM-768 key pair
  (`KeyGen_internal(d, z)`) and its ML-DSA-65 key pair (`KeyGen_internal(ξ = HKDF-SHA-512(seed,
  "SINO/V1/DEVICE-ALERT-SIGNER", 32))`). An entry holds no copy of the RMK: a device keeps its seed while locked, so
  such a copy would open the vault without the password.
- **Device names:** `deviceInfoBase64` holds the device's name and type, so the cloud never sees them:
  `base64(iv(12) || AES-256-GCM(domain key "SINO/V1/DEVICE-INFO", utf8(json)))`, where the JSON is
  `{"keyId": "<device id>", "name": "…", "type": "…"}` padded with spaces to a multiple of 128 bytes (so its size
  does not give the name's length). A reader must check that `keyId` is the envelope's own. It is null when a device
  has no name.
- **Revocation:** a revoked device moves from `keyEnvelopes` to `revokedKeyIds`, the epoch increases and the list is
  re-signed. Each device pins the signer key and the newest epoch it accepted. It wipes itself (that device only)
  when a list that verifies names it in `revokedKeyIds`. Being missing from the envelopes is not a revocation.
  Revocation is a kill switch for a lost device, not a cryptographic lock-out: every device has held the RMK.
- **Wrong-password alerts** (`security/alert_<device id>.json`, opt-in per device): `{ "format": "SINO-DEVICE-ALERT",
  "version": 1, "senderKeyId", "sequence", "copies": [ { "recipientKeyId", "encapsulationBase64", "sealedBase64" } ],
  "signatureBase64" }`. Each copy seals the report `{"senderKeyId", "sequence", "failedAttempts", "unlockedAfter",
  "reportedAt"}` (JSON padded with spaces to a multiple of 128 bytes) as `base64(iv(12) || AES-256-GCM(HKDF-SHA-512(
  sharedSecret, "SINO/V1/DEVICE-ALERT|<sender>|<recipient>|<sequence>", 32)))`, where the shared secret comes from
  ML-KEM-768 encapsulation to the recipient's `kemPublicKeyBase64`. The signature is ML-DSA-65 by the sender's
  `signingPublicKeyBase64` over the JSON with `signatureBase64` null. A reader refuses a sequence not newer than the
  last it accepted from that sender. Recovery does not need these files.

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

## 12. Managed vaults: recovery from organisation kits

A vault enrolled with a company's Sino Control Hub keeps a **recovery file**: its `RMK || vault salt` sealed to the
organisation's recovery key. The key is split into **organisation kits**, one per admin, and any `threshold` of them
rebuild it. Kits and the recovery file open the vault without Sino, its apps or its hub. The company takes the
recovery file from its hub's console (Vaults and recovery) or from its own storage (`sino-hub/recovery/<vault>.sinorecovery`).

```bash
java -jar build/libs/sino-recovery-<version>.jar recover --vault <SinoVault copy> --out <folder> \
    --recovery-file vault.sinorecovery --kit alice.sinokit --kit bob.sinokit [--kit-passphrases <file>]
```

**Kits** (`SINO-ORG-KIT`, version 1), JSON: `orgId`, `orgName`, `kitSetId` (16 bytes, hex), `createdAt`, `holder`,
`threshold`, `shareCount`, `shareIndex`, `shareBase64` (32 bytes), `rootPublicKeyBase64` (ML-DSA-65),
`recoveryPublicKey`, `sealedRsaPrivateKeyBase64` and `rsaKeyInHsm` (null, or `{label, publicKeySpkiBase64}`), signed
with the root key (ML-DSA-65 over the JSON with `signatureBase64` null, fields in this order, every field written).

- `recoveryPublicKey`: base64url (no padding) of `[version][u16 rsaLength][RSA SPKI][ML-KEM-768 public key]`, version 1;
  version 2 when the RSA half is in the organisation's HSM, whose RSA-OAEP uses MGF1-SHA-256.
- `rsaKeyInHsm`: when the organisation keeps the recovery key's RSA half in a hardware security module or cloud key
  service, the kits hold no RSA private key (`sealedRsaPrivateKeyBase64` is empty) and name that key: its `label`
  there and its public key, which must be `recoveryPublicKey`'s. Paper kits carry it too.
- A kit sealed with a passphrase (`SINO-ORG-KIT-SEALED`) keeps its header readable (`content`, `orgId`, `orgName`,
  `kitSetId`, `holder`, `shareIndex`, `shareCount`, `threshold`, `saltBase64`) and holds the kit in `sealedBase64`:
  `iv(12) || AES-256-GCM(key, iv, kit JSON)`, `key = HKDF-SHA-512(Argon2id(passphrase, salt), "SINO/V1/ORG-KIT-SEAL|" || kitSetId, 32)`
  (Argon2id as in §4). The kit inside must match the header.
- A paper kit (`SINO-ORG-PAPER-KIT`) leaves out the public keys and the signature and has `rootFingerprint` instead
  (base64url SHA-256 of the root public key). Printed, its text (sealed or not) is cut into QR codes
  `SINOKIT1:<part>/<parts>:<kitSetId>:<text>`, which join in any order.

**Combining.** The shares are Shamir shares of a 32-byte secret `S`, byte by byte over GF(2^8) with the AES
polynomial `x^8 + x^4 + x^3 + x + 1`; `S` is the polynomial at 0 (Lagrange). With `ctx = orgId || "|" || kitSetId`:
- root key: `ML-DSA-65.KeyGen_internal(HKDF-SHA-512(S, "SINO/V1/ORG-ROOT|" || ctx, 32))`;
- recovery key, ML-KEM half: `ML-KEM-768.KeyGen_internal(HKDF-SHA-512(S, "SINO/V1/ORG-RECOVERY-KEM|" || ctx, 64))` (d || z);
- recovery key, RSA half: `sealedRsaPrivateKeyBase64` is `iv(12) || AES-256-GCM(HKDF-SHA-512(S, "SINO/V1/ORG-KIT-RSA|" || ctx, 32), iv, PKCS#8)`,
  or with `rsaKeyInHsm`, the key in the HSM (nothing to open).

The kits must be of one ceremony (same fields but holder, index and share), with distinct indexes, at least
`threshold` of them. Shamir cannot tell that wrong shares were combined, so the result is checked: the RSA key must
open (unless it is in an HSM), and the derived keys must match the kits' public keys (and the root fingerprint).

**The recovery file** (`SINO-ORG-RECOVERY`, version 1): `orgId`, `vaultId`, `kitSetId`, `deviceId`, `createdAt` and
`sealedBase64`, the hybrid container of §4 (legacy handover): `"SINO" || 3 || u16 rsaLength || rsaCt || kemCt(1088) || iv(12) || gcm`.
- `kemSecret = ML-KEM-768.Decaps(kemCt)`, `rsaSecret = RSA-OAEP(SHA-256, MGF1-SHA-1).Decrypt(rsaCt)` (32 bytes); with
  the RSA half in an HSM, the HSM decrypts `rsaCt` with RSA-OAEP(SHA-256, MGF1-SHA-256) (PKCS#11 `CKM_RSA_PKCS_OAEP`,
  Azure Key Vault `RSA-OAEP-256`, AWS KMS `RSAES_OAEP_SHA_256`, Google Cloud KMS `RSA_DECRYPT_OAEP_*_SHA256`), and its
  answer, 32 bytes, is `rsaSecret`. The tool prints `rsaCt` and takes the answer with `--hsm-answer <base64>`;
- `kek = HKDF-SHA-512(kemSecret || rsaSecret, "SINO/V1/ORG-RECOVERY|" || orgId || "|" || vaultId || "|" || kitSetId || "|" || hex(SHA-256(kemCt || rsaCt || rsaSpki || mlKemPublicKey)), 32)`,
  hex in lower case;
- the payload `AES-256-GCM(kek, iv)` is `RMK(32) || vault salt`, which opens the vault as §4's backup does.

The file opens only with the kits of the set it names. After a kit rotation, a vault's file is sealed to the new kits
once one of its devices has unlocked; until then, the previous kits open it.

## 13. Shared folders

Vaults of one organisation share folders end to end encrypted. A folder has keys of its own, separate from every
member's vault key, and lives in the organisation's storage at `shares/<share id>/` (on Azure, a container of its own):

```text
share_manifest.json                         the folder's newest manifest
metadata/<HMAC(salt, "share-batch:" || writer)>.batch    one batch per writer (a member vault's device)
blobs/<HMAC(salt, "share-blob:" || revision id)>.enc     each revision's content
```

Names are the first 16 bytes of `HMAC-SHA256(salt, label)`, lower-case hex. A **writer** is `<vault id>/<16 hex digits>`.

```bash
java -jar build/libs/sino-recovery-<version>.jar share-recover --share <copy of shares/<id>> --out <folder> \
    --kit alice.sinokit --kit bob.sinokit [--include-trashed] [--kit-passphrases <file>]
```

**The manifest** (`SINO-SHARE-MANIFEST`, version 1), JSON, every field written in this order: `format`, `version`,
`orgId`, `shareId` (16 bytes, hex), `manifestVersion`, `epoch`, `previousHash`, `nameBase64`, `members`, `keys`,
`kitSetId`, `orgRecoveryBase64`, `issuedAt`, `signedBy`, `signatureBase64`.
- `members`: `vaultId`, `role` (`OWNER`, `EDITOR`, `VIEWER`), `signerBase64` (ML-DSA-65 public key) and `receiver`
  (the recipient token of §12: RSA SPKI and ML-KEM-768 public key).
- `keys`: per member, `vaultId` and `sealedBase64`: the **key bundle** sealed to its receiver.
- `orgRecoveryBase64`: the same bundle sealed to the organisation recovery key of kit set `kitSetId`.
- `nameBase64`: `iv(12) || AES-256-GCM(nameKey(epoch), iv, utf-8 name)`.
- `signatureBase64`: ML-DSA-65 over the JSON with the signature null, by member `signedBy` (an owner of the previous
  version), or by the organisation root key when `signedBy` is `org-root` (company recovery). `previousHash` is
  lower-case hex SHA-256 of the previous version's JSON, signature included ("" for version 1). Removing a member
  always starts a new `epoch`. Sino's apps check this chain from version 1 against the hub; a copy of the storage
  holds only the newest version.

**The key bundle**, JSON `shareId`, `epoch`, `saltBase64` (32 bytes) and `keysBase64` (the share keys of epochs 1 to
`epoch`, 32 bytes each), in the hybrid container of §12, opened as there with the label:
- for a member: `"SINO/V1/SHARE-KEYS|" || shareId || "|" || vaultId || "|" || epoch || "|"`;
- for the organisation: `"SINO/V1/SHARE-ORG-RECOVERY|" || orgId || "|" || shareId || "|" || epoch || "|" || kitSetId || "|"`.

From a share key `K` of an epoch: `batchKey = HMAC-SHA256(K, "SINO/V1/SHARE-BATCH" || 0x01)` and
`nameKey = HMAC-SHA256(K, "SINO/V1/SHARE-NAME" || 0x01)`.

**A member's receiving key.** A member vault keeps it at `security/share_identity.bin` in its own storage:
`iv(12) || AES-256-GCM(HMAC-SHA256(RMK, "SINO/V1/SHARE-IDENTITY" || 0x01), iv, JSON)`, the JSON holding `format`
(`SINO-SHARE-IDENTITY`), `version` (1), `kemSeedBase64` (64 bytes, `d || z`), `rsaPrivateKeyPkcs8Base64` and
`rsaPublicKeySpkiBase64`. Its signing key is `ML-DSA-65.KeyGen_internal(HMAC-SHA256(RMK, "SINO/V1/SHARE-IDENTITY-SIGNER" || 0x01))`.
So the vault's recovery phrase, or its recovery file and the kits, open its folders too.

**Batches** (`SINO-SHARE-BATCH`, version 1): `format`, `version`, `shareId`, `writer`, `sequence`, `epoch`,
`sealedBase64` and `signatureBase64`, ML-DSA-65 over the JSON with the signature null, by the writer's vault.
`sealedBase64` is `iv(12) || AES-256-GCM(batchKey(epoch), iv, JSON)` of `shareId`, `writer`, `sequence`, `writtenAt`,
`entries`, `editing` and `retired`. A batch counts only when its vault is an owner or editor of the manifest, its signature verifies, it
sits at its writer's name, and its inner fields match the envelope.

**Entries** (one revision each): `fileId`, `revisionId` (16 bytes, hex each), `name`, `mimeType`, `size`, `checksum`
(hex SHA-256 of the plaintext), `modifiedAt`, `author` (vault id), `clock` (writer to count), `keyEpoch`,
`wrappedDekBase64` (`iv(12) || AES-256-GCM(K of keyEpoch, iv, DEK)`), `ivBase64`, `encryptionVersion` (2),
`blobName`, `trashed`, `deleted`, `parentId` and `folder`. The blob is the chunked format of §2 under the DEK and iv.
A `folder` entry is a subfolder, with no content (empty `blobName`, size 0); `parentId` names the subfolder an entry
sits in (a folder entry's `fileId`), "" for the top.

**Retired** (`retired`, possibly empty): content the writer's revisions replaced, each `blobName` and `since`, which
the writer deletes 7 days later unless a current revision uses it again. It need not be read to recover a folder.

**Edit marks** (`editing`, possibly empty): the files the writer is editing outside Sino, each `fileId`, `revisionId`
(the revision the copy came from), `baseClock` (its clock), `since` and `until` (at most 24 hours later). They are
hints for the other members ("Bob is editing this file") and need not be read to recover a folder. The writer's next
revision of the file builds on `baseClock`, so a revision someone else made meanwhile stays beside it as a conflict.

**Merging.** A revision replaces another of the same file when its clock is at least the other's for every writer
and more for one. The file's current revisions are those nothing replaces: a `deleted` one hides the file unless a
live one stands beside it; live ones not in the trash come before trashed ones. Two or more live revisions are a
conflict: the earliest (by `modifiedAt`, then `revisionId`) keeps the name, the others become
`<name> (conflict, <author>, <yyyy-mm-dd>)<extension>`, with the date in UTC.

**Subfolders.** A subfolder's revision that counts is, of its current ones, one not in the trash, then the latest (by
`modifiedAt`, then `revisionId`). An entry sits in the subfolder `parentId` names, or at the top when that subfolder is
gone or the entry is a subfolder whose parents lead back to itself. What sits in a subfolder in the trash is in the
trash with it. `share-recover` writes subfolders as directories.
