# Sino Cryptographic Specification & Architecture

This document provides the formal open specification for **Sino's Zero-Knowledge Encryption Layer**.

---

## 1. Cryptographic Key Hierarchy

Sino enforces a 4-tier cryptographic key hierarchy to ensure local encryption and RAM isolation:

```
[ User Password / PIN ]
          │
          ▼  (Argon2id - 64MB RAM, 3 iterations, 4 parallelism)
[ Password Hash / Key ]
          │
          ▼  (AES-256-GCM Unwrap)
[ Root Master Key (RMK) ]
          │
          ▼  (HKDF-HMAC-SHA256 Domain Separation)
[ Domain-Specific Key ] (e.g., Auth, Sync, Metadata)
          │
          ▼  (AES-256-GCM Key Wrapping)
[ Data Encryption Key (DEK) ] ──▶ Encrypts Payload Bytes
```

---

## 2. Encryption Engine Specification (Protocol v3)

- **Algorithm**: AES-256-GCM (`AES/GCM/NoPadding`)
- **Key Length**: 256 bits (32 bytes)
- **IV Length**: 96 bits (12 bytes)
- **Authentication Tag Length**: 128 bits (16 bytes)

### 2.1 Chunked GCM Streaming Specification (Encryption v2)
For large files and direct cloud media streaming:
1. Payloads are divided into **1MB fixed chunks** (1,048,576 bytes).
2. Each chunk is encrypted as an independent GCM packet (Plaintext + 16-byte Tag).
3. **Nonce Derivation (v2)**: The last 4 bytes of the base 96-bit IV are overwritten with the 32-bit big-endian chunk counter.
   $$\text{IV}_{\text{chunk}} = \text{BaseIV}[0..7] \parallel \text{BigEndian32}(\text{ChunkIndex})$$
4. **Legacy Support (v1)**: Older versions used XOR derivation ($\text{BaseIV} \oplus \text{BigEndian32}(\text{ChunkIndex})$). Modern Sino engines detect the version from metadata and maintain bit-perfect compatibility.

---

## 3. Cloud Blindness & RAID Path Anonymization

Sino converts human-readable filenames and relative folder paths into opaque, un-linkable cloud object keys using **Salted HMAC-SHA256**. To ensure forensic privacy and filesystem compatibility, these hashes are truncated according to the **RAID Discovery Standard**:

### 3.1 Standard Truncation Lengths
- **Cloud Folders**: HMAC-SHA256 hash of the relative path, truncated to **16 characters** (hex).
- **Deterministic Filenames**: HMAC-SHA256 hash of the file checksum, truncated to **16 characters** (hex).
- **Metadata Batch Names**: HMAC-SHA256 hash of the logical identifier, truncated to **12 characters** (hex) with a `.batch` suffix.

### 3.2 Dictionary Attack Defense
The use of a high-entropy, hardware-wrapped **Vault Salt** ensures that cloud providers cannot perform dictionary attacks (pre-computing hashes of common filenames) to identify user data.

---

## 4. Technical Artifact Wrapping (v2 Standard)

All system-level artifacts (Metadata batches, Snapshots, Backups) are enclosed in an authenticated container to prevent cloud-side tampering or bit-rot:

**[ MAGIC (4B) ] [ VERSION (1B) ] [ IV (12B) ] [ ENCRYPTED_DATA (NB) ] [ SHA256_CHECKSUM (32B) ]**

1. **Magic**: Constant `SINO`.
2. **Version**: Current standard is `2`.
3. **Integrity**: The trailing 32-byte SHA-256 hash covers the entire packet from MAGIC to the end of the ciphertext. Any artifact failing this check is rejected as "Forensically Compromised."

---

## 5. Dual-Vault Duress Isolation Specification

- Primary Vault and Decoy (Duress) Vault use **domain-separated Argon2id salts**:
  - `SinoPrimaryMasterKeySaltV1` for Primary Vault
  - `SinoDuressDecoyKeySaltV1` for Decoy Vault
- Primary keys and Decoy keys share zero mathematical linkage. Analyzing the algorithm or code structure gives zero cryptographic indicator of whether a secondary decoy vault exists.

---

## 6. Memory Hygiene Specification

All transient sensitive byte arrays (`ByteArray` representing DEK, RMK, or plaintexts) are explicitly zeroed out in `finally` blocks using `SecurityUtils.fillZero(array)` to prevent data extraction from memory dumps.

---

## 7. Metadata Specification

Sino utilizes a structured JSON format for file metadata. This metadata is the "Source of Truth" for the RAID engine.

### 7.1 Data Fields
- `originalName`: The original filename (including extension).
- `relativePath`: The logical directory structure.
- `mimeType`: Technical file classification.
- `size`: Original file size in bytes.
- `checksum`: SHA-256 fingerprint of the original plaintext.
- `cloudChecksum`: SHA-256 fingerprint of the final optimized/transcoded blob.
- `encryptionVersion`: Format version (1 = XOR nonce, 2 = Counter nonce).
- `encryptedDEK`: The file's unique 256-bit AES key, wrapped by the RMK.
- `iv`: The base 96-bit Initialization Vector.
- `isCompressed`: Gzip optimization flag.
- `isChunked`: supports 1MB GCM chunked random access.
- `isDuress`: Forensic isolation flag.
- `providerHints`: A list of RAID targets (e.g., `["MEGA", "GOOGLE_DRIVE", "S3:100"]`).

---

## 8. Post-Quantum Cryptography (PQC v1) Protocol Architecture

Sino v2.0+ implements post-quantum cryptographic protection against future quantum computing decryption threats (e.g., Shor's algorithm).

### 8.1 Cryptographic Suite Identifier
`SINO-VAULT-V1-AES256GCM-HKDFSHA512-MLKEM768`

### 8.2 Key Encapsulation Mechanism (ML-KEM-768)
- **Standard**: NIST FIPS 203 (ML-KEM-768)
- **Public Key Length**: 1,184 bytes
- **Private Key Length**: 2,400 bytes
- **Ciphertext Length**: 1,088 bytes
- **Shared Secret Length**: 32 bytes (256 bits)
- **Usage**: Used to establish post-quantum secure key exchange between devices without transmitting raw vault keys over network channels.

### 8.3 Digital Signatures (ML-DSA-65)
- **Standard**: NIST FIPS 204 (ML-DSA-65)
- **Public Key Length**: 1,952 bytes
- **Private Key Length**: 4,032 bytes
- **Signature Length**: 3,309 bytes
- **Usage**: Provides post-quantum digital signatures binding `VaultManifest` headers, key envelopes, and security metadata.

### 8.4 Domain-Separated HKDF-SHA-512
All key derivations use HKDF-SHA-512 with strict domain separation:
- **Vault Key Derivation**:
  $$\text{VaultKey} = \text{HKDF-SHA-512}(\text{salt}=\text{null}, \text{IKM}=\text{RootMasterKey}, \text{info}=\text{"SINO/V1/VAULT"}, \text{length}=32)$$
- **File DEK Derivation**:
  $$\text{FileDEK} = \text{HKDF-SHA-512}(\text{salt}=\text{null}, \text{IKM}=\text{VaultKey}, \text{info}=\text{"SINO/V1/FILE/"} \parallel \text{FileID}, \text{length}=32)$$

### 8.5 Multi-Device Key Envelopes (`KeyEnvelope`)
Vault keys are encrypted for each authorized device using AES-256-GCM keyed by the device's ML-KEM-768 shared secret:
$$\text{EncryptedVaultKey} = \text{AES-256-GCM-Encrypt}(\text{Key}=\text{SharedSecret}_{\text{MLKEM}}, \text{IV}=\text{Nonce}_{96}, \text{Data}=\text{VaultKey})$$

Each `KeyEnvelope` contains:
- `keyId`: Device Identifier (String)
- `ciphertextBase64`: Base64-encoded `EncryptedVaultKey`
- `nonceBase64`: Base64-encoded 96-bit AES-GCM IV
- `pqcEncapsulationBase64`: Base64-encoded ML-KEM-768 ciphertext (1,088 bytes)

### 8.6 Device Revocation & Nuclear Self-Destruct
- **Revocation**: Removing a device's `KeyEnvelope` from `VaultManifest` increments `keyEpoch` and re-signs the manifest with ML-DSA-65.
- **Nuclear Self-Destruct Protocol**: When a client evaluates the cloud `VaultManifest` during unlock or sync initialization and discovers its device ID has been revoked, it halts all operations and executes `triggerNuclearWipe()`, purging RAM keys (`fillZero`), local databases, and hardware keys.

### 8.7 Standalone CLI Recovery (`SinoDecryptorCLI`)
Privacy auditors and users can recover encrypted blobs on Linux, macOS, or Windows using the standalone SDK CLI:
```bash
java -cp sino-open-sdk.jar com.sino.sdk.cli.SinoDecryptorCLI --pqc <manifest_file> <device_id> <b64_mlkem_privkey> <input_file> <output_file> <file_id> <base64_iv> [b64_mldsa_pubkey]
```
