# Sino Privacy Vault Open Security SDK

Welcome to the official security core of **Sino**.

Sino is a privacy-first encryption layer designed to sit on top of your existing
cloud storage. This repository contains the reference implementation of our
**Zero-Knowledge Architecture**, including our **Post-Quantum Cryptography (PQC v1)** protocol. By open-sourcing these core components, we
provide the community and security researchers with the means to verify our
privacy claims.

---

## 🛡️ The Sino Trust Mandate

We believe that in the realm of privacy, **if it is not verifiable, it is not
secure.**

This SDK includes the actual cryptographic engines used by the Sino application
to ensure that:

1. All encryption happens locally on your device before network transmission.
2. Only you—not Sino, not cloud providers, and not any third party—hold the keys
   to your data.
3. Cloud providers are treated as "dumb storage," remaining completely blind to
   your filenames, structures, and content.
4. Your data is protected against future quantum computing decryption threats (e.g., Shor's algorithm) via NIST FIPS 203 & 204 post-quantum standards.

---

## 📂 Included Components & Specifications

- **[`SPECIFICATION.md`](SPECIFICATION.md)**: Formal open specification for
  Sino's 4-tier key hierarchy, path salting, 1MB chunked GCM streaming, and **Post-Quantum Cryptography (PQC v1) Protocol Architecture**.
- **`crypto/AESEncryptionEngine.kt`**: Implementation of AES-256-GCM, including
  **Encryption v2 (Protocol v3)** with standardized big-endian counter nonces.
- **`crypto/HKDFEngine.kt`**: Implementation of **domain-separated HKDF-SHA-512** for vault key (`SINO/V1/VAULT`) and per-file DEK (`SINO/V1/FILE/`) derivation.
- **`crypto/MLKEMEngine.kt`**: Implementation of **NIST FIPS 203 ML-KEM-768** post-quantum key encapsulation mechanism.
- **`crypto/MLDSAEngine.kt`**: Implementation of **NIST FIPS 204 ML-DSA-65** post-quantum digital signatures for signing vault manifests.
- **`crypto/DeviceKeyManager.kt`**: Multi-device key envelope (`KeyEnvelope`) creation, AES-256-GCM + ML-KEM shared secret unwrapping, and device revocation filtering.
- **`crypto/VaultMigrationEngine.kt`**: Auto-migration engine upgrading legacy vault manifests to PQC v1 headers (`SINO-VAULT-V1-AES256GCM-HKDFSHA512-MLKEM768`).
- **`crypto/SinoKeyDerivation.kt`**: Implementation of **Argon2id** (64MB RAM, 3
  iterations, 4 parallelism threads) for high-entropy key derivation.
- **`crypto/CloudPathHasher.kt`**: HMAC-SHA256 path anonymizer implementing
  standardized RAID truncation (16/12 characters) for complete "Cloud Blindness".
- **`crypto/DuressKeyDerivation.kt`**: Domain-separated key derivation
  specification for dual-vault decoy key isolation.
- **`cli/SinoDecryptorCLI.kt`**: Standalone desktop CLI recovery runner supporting direct DEK mode and PQC v1 manifest recovery (`--pqc`).
- **`cloud/CloudClient.kt`**: Interface defining our "Blind Cloud" protocol.
- **`crypto/KeyEnvelope.kt`**: Versioned `KeyEnvelope` and `VaultManifest` serializable data models.

---

## 🚀 Usage Instructions

### 1. Building the SDK Jar & Running Tests

To compile the SDK and execute the unit test suite on any platform (Linux,
macOS, Windows):

```bash
# Run unit test suite
./gradlew test

# Package the standalone JAR artifact
./gradlew jar
```

### 2. Standalone Desktop File Recovery (CLI)

Users can recover and decrypt their Sino files on any desktop operating system
independently of the official application binaries.

#### A. Direct DEK / IV Mode
```bash
# Syntax
java -cp build/libs/sino-open-sdk-3.2.0.jar com.sino.sdk.cli.SinoDecryptorCLI <input_file> <output_file> <base64_dek> <base64_iv> [is_chunked] [encryption_version]

# Example
java -cp build/libs/sino-open-sdk-3.2.0.jar com.sino.sdk.cli.SinoDecryptorCLI video.enc video.mp4 K7aB...== Iv9x...== true 1
```

#### B. PQC v1 Vault Manifest Mode
```bash
# Syntax
java -cp build/libs/sino-open-sdk-3.2.0.jar com.sino.sdk.cli.SinoDecryptorCLI --pqc <manifest_file> <device_id> <b64_mlkem_privkey> <input_file> <output_file> <file_id> <base64_iv> [b64_mldsa_pubkey]

# Example
java -cp build/libs/sino-open-sdk-3.2.0.jar com.sino.sdk.cli.SinoDecryptorCLI --pqc manifest.json device-01 mlkemKey...== doc.enc doc.pdf 1005 Iv9x...== mldsaKey...==
```

---

## 🔐 Programmatic Integration Examples (Kotlin / Java)

### A. Post-Quantum Key Encapsulation (ML-KEM-768)

```kotlin
import com.sino.sdk.crypto.MLKEMEngine

val mlKem = MLKEMEngine()
val keyPair = mlKem.generateKeyPair()

// Encapsulate shared secret using device's ML-KEM-768 public key
val (ciphertext, sharedSecretEnc) = mlKem.encapsulate(keyPair.publicKey)

// Decapsulate shared secret using device's ML-KEM-768 private key
val sharedSecretDec = mlKem.decapsulate(ciphertext, keyPair.privateKey)

keyPair.zeroize()
```

### B. Post-Quantum Manifest Digital Signatures (ML-DSA-65)

```kotlin
import com.sino.sdk.crypto.MLDSAEngine

val mlDsa = MLDSAEngine()
val keyPair = mlDsa.generateKeyPair()

val payload = manifest.toJson().encodeToByteArray()
val signature = mlDsa.sign(payload, keyPair.privateKey)

val isValid = mlDsa.verify(payload, signature, keyPair.publicKey)
keyPair.zeroize()
```

### C. Domain-Separated HKDF-SHA-512 Key Derivation

```kotlin
import com.sino.sdk.crypto.HKDFEngine

val hkdf = HKDFEngine()

// Derive Vault Key from Root Master Key
val vaultKey = hkdf.deriveVaultKey(rootMasterKey)

// Derive per-file DEK using Vault Key and File ID
val fileDek = hkdf.deriveFileKey(vaultKey, fileId = 1001L)
```

---

## 🤖 AI-Augmented Security Auditing

The development of this SDK and the broader Sino architecture involved the use
of **Advanced Artificial Intelligence (AI)** as a continuous security auditor.

Throughout the implementation phase, AI was utilized to:

- **Resilience Testing**: Perform real-time analysis of cryptographic
  implementations to ensure adherence to global standards.
- **Memory Hygiene**: Verify that RAM sanitization logic (e.g.,
  `SecurityUtils.fillZero`) is consistently applied to prevent forensic data
  extraction.
- **Pattern Validation**: Audit the "Cloud Blindness" protocols to ensure no
  metadata or structural identifiers are leaked to third-party storage
  providers.

By combining human architectural design with AI-driven auditing, we have created
a hardened foundation for personal digital sovereignty.

---

## ⚖️ License & Contributions

This SDK is released under the MIT License. We welcome peer reviews and security
audits.

---

_For more information on the Sino project, visit
[Sino Privacy](https://sinosecure.app/privacy)._
