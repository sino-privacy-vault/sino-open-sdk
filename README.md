# Sino Privacy Vault Open Security SDK

Sino is a privacy-first encryption layer on top of your existing cloud storage. This repository is its open
security core:

- **The specification.** [`SPECIFICATION.md`](SPECIFICATION.md) describes exactly what Sino stores in your cloud
  accounts and how it is encrypted.
- **An independent implementation.** The SDK reads and verifies that data with no dependency on the Sino apps.
- **A recovery tool.** With your 24-word recovery phrase and a downloaded copy of your cloud folder, you can decrypt
  every file without Sino.

The tests recover a vault written by Sino's own code, so the specification, this SDK and the apps cannot silently
disagree.

> **If it is not verifiable, it is not secure.** Everything is encrypted on your device before upload. Cloud
> providers see only opaque names and ciphertext, and only your recovery phrase or your unlocked devices can open
> the vault.

---

## Recover your files without the Sino apps

1. **Download your vault.** From each cloud provider you used (MEGA, Google Drive, S3, Azure Blob Storage), download the `SinoVault`
   folder. One provider is enough if it holds everything. Give several and the tool merges them and fills gaps.
2. **Build the tool.** You need a Java 17+ JDK:
   ```bash
   ./gradlew recoveryJar        # builds build/libs/sino-recovery-4.0.0.jar (self-contained)
   ```
3. **Recover:**
   ```bash
   java -jar build/libs/sino-recovery-4.0.0.jar recover \
       --vault ~/Downloads/mega/SinoVault --vault ~/Downloads/drive/SinoVault --out ~/Recovered
   ```
   You are asked for the recovery phrase with the input hidden. You can instead use `--phrase-file <file>`, or
   `--phrase-stdin` to pipe it in. The phrase is never accepted as an argument, where it would land in shell
   history and process listings.

Other commands:

| Command | What it does |
| --- | --- |
| `list --vault <dir> …` | Lists every file, how many provider copies exist and whether it is in the trash. |
| `verify-manifest --vault <dir> …` | Verifies the vault's signed device list (ML-DSA-65) and shows the enrolled and revoked devices. |
| `recover … --include-trashed` | Also recovers files that are in Sino's trash. |

What recovery guarantees:

- It makes no network connections.
- It never overwrites files that already exist.
- Each file is checked against the checksum recorded when it was encrypted, and any modified byte fails
  authentication. A damaged copy is discarded and another provider's copy is used, so you never get a corrupted
  file silently.
- Metadata batches that were moved or tampered with are reported and ignored. Names that could escape the output
  folder are refused.
- Exit codes: `0` everything recovered, `1` some files failed (listed), `2` the vault could not be opened.

Only the real vault can be recovered. The decoy (duress) vault is bound to one device's hardware by design; see
§9 of the specification.

---

## Components

| Package | Contents |
| --- | --- |
| `crypto` | AES-256-GCM with the chunked format 2 (identical to Sino's engine), HKDF-SHA-512, Argon2id, ML-KEM-768 and ML-DSA-65 (BouncyCastle, an independent implementation), device-list entries (public keys and sealed device names), the manifest models, and strict String-free encoders (`SecurityUtils`). |
| `vault` | The vault format: root-key schedule (`VaultKeys`), recovery backup (`RecoveryKit`), artifact container, cloud layout, metadata batches (decode, placement check, cross-provider merge), manifest verification and `VaultRecovery`. |
| `cli` | The recovery tool (`SinoDecryptorCLI`). |
| `util` | Sino's log sanitizer (`SinoPrivacyEngine`), the same rules the apps apply before anything is written to a log. |

Dependencies: BouncyCastle (`bcprov`) and kotlinx-serialization. There are no cloud SDKs and no network code.

## Programmatic use (Kotlin)

```kotlin
import com.sino.sdk.vault.RecoveryKit
import com.sino.sdk.vault.VaultRecovery
import java.io.File

val words = RecoveryKit.splitWords(phraseChars)            // CharArrays; wipe them afterwards
VaultRecovery.open(listOf(File("mega/SinoVault"), File("drive/SinoVault")), words).use { vault ->
    vault.index().files.forEach { println("${it.path} (${it.copies.size} copies)") }
    val report = vault.recover(File("Recovered"))
    report.failed.forEach { println("FAILED $it") }
    println(vault.verifyManifest().manifest?.revokedKeyIds)
}
```

Lower-level building blocks:

```kotlin
val kem = MLKEMEngine()                                    // FIPS 203
val device = kem.keyPairFromSeed(seed64)                   // d || z, as Sino keeps it per device
val (ciphertext, secret) = kem.encapsulate(device.publicKey)

val dsa = MLDSAEngine()                                    // FIPS 204, pure, empty context
VaultKeys(rootKey).use { keys ->
    val verifier = ManifestVerifier.forVault(keys)          // signer and vault id derived from the root key
    verifier.verifies(VaultManifest.fromJson(json))
}
```

## Building and testing

```bash
./gradlew test          # unit tests, NIST ACVP key-generation vectors, and recovery of a vault written by Sino itself
./gradlew recoveryJar   # the self-contained recovery tool
```

The interop fixture (`src/test/resources/fixtures/core-vault`) is regenerated from the Sino repository whenever a
format changes; see its README.

## Security and license

See [`SECURITY.md`](SECURITY.md) for responsible disclosure. Released under the MIT License. Peer reviews and audits
are welcome.

_More about Sino: [Sino Privacy](https://sinosecure.app/privacy)._
