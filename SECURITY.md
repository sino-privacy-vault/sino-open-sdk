# Security Policy

**Sino Privacy Vault Open Security SDK (`sino-open-sdk`)**  
**Repository:** [https://github.com/sino-privacy-vault/sino-open-sdk](https://github.com/sino-privacy-vault/sino-open-sdk)  
**Security Portal:** [https://sinosecure.app/security#bug-bounty](https://sinosecure.app/security#bug-bounty)  

---

## 🛡️ Our Security Commitment

Sino is engineered under the strict principles of **Zero-Knowledge Architecture**, **Total Cloud Blindness**, and **Post-Quantum Cryptographic Readiness (PQC v1)**. We consider the security and cryptographic integrity of our open-source SDK to be of paramount importance.

We actively encourage independent cryptographers, security researchers, and privacy auditors to inspect our threat models and audit our source code implementations. If you discover a security vulnerability, cryptographic flaw, or privacy issue, we appreciate your help in disclosing it to us responsibly.

---

## 📋 Supported Versions

We provide security patches and cryptographic errata for the following versions:

| Version | Supported | Notes |
| :--- | :---: | :--- |
| `3.2.x` | ✅ Yes | Current stable release with Post-Quantum Cryptography (PQC v1) |
| `3.1.x` | ✅ Yes | Protocol v2 chunked GCM streaming |
| `< 3.1.0` | ❌ No | Deprecated legacy formats; upgrade recommended |

---

## 🚨 Reporting a Vulnerability

Please **do NOT** disclose security vulnerabilities publicly through open GitHub issues, pull requests, or public forums. Public disclosure before a fix is available puts users and sensitive archives at risk.

You can report vulnerabilities to our security team via either of the following channels:

### Option A: GitHub Private Vulnerability Reporting (Recommended)

The most direct and secure way to report a vulnerability is via GitHub's Private Vulnerability Reporting interface:

1. Navigate to the [Private Vulnerability Advisory Submission](https://github.com/sino-privacy-vault/sino-open-sdk/security/advisories/new) page.
2. Complete the vulnerability advisory form with technical details, steps to reproduce, and impact assessment.
3. Our core security team will be notified directly and can collaborate with you privately on a patch within a confidential temporary fork.

### Option B: PGP-Encrypted Email

If you prefer to communicate via email, send your report to:

* **Security Email:** [`support@sinosecure.app`](mailto:support@sinosecure.app)
* **Subject Line:** `[SECURITY DISCLOSURE] Vulnerability in sino-open-sdk - <Summary>`
* **PGP Public Key:** [https://sinosecure.app/sino-security.asc](https://sinosecure.app/sino-security.asc)
* **PGP Key ID:** `741269C3`
* **PGP Fingerprint:** `7B52 729E E9A9 1445 D9BE 1F46 AEEE B140 7412 69C3`

Please encrypt your report using our official PGP key to protect the details in transit. Include your own PGP public key if you would like us to reply with encrypted communications.

---

## 📝 What to Include in Your Report

To help us investigate and triage your report promptly, please include:

1. **Component / Module Affected:** Identify the specific engine (e.g., `MLKEMEngine`, `MLDSAEngine`, `AESEncryptionEngine`, `DeviceKeyManager`, `VaultMigrationEngine`, `CloudPathHasher`, `SinoDecryptorCLI`).
2. **Vulnerability Type:** (e.g., key exposure, shared secret bypass, side-channel attack, nonce reuse, memory hygiene failure, path de-anonymization).
3. **Proof-of-Concept (PoC):** Step-by-step instructions, test vectors, or sample code that demonstrates the vulnerability.
4. **Impact Assessment:** Explain the practical attack scenario and potential consequences (e.g., local privilege escalation, ciphertext recovery, cloud provider de-anonymization).
5. **Suggested Mitigation (Optional):** Any recommended code patches, defensive checks, or algorithmic adjustments.

---

## 🎯 Scope & Severity Matrix

Our security team classifies reported issues based on practical impact according to our published security matrix:

| Severity | Category | Example Scenarios |
| :--- | :--- | :--- |
| **Critical** | **Vault Key Compromise** | Unauthenticated remote key extraction, cipher bypass, ML-KEM-768 shared secret recovery, AES-GCM nonce collision generation, or unauthorized master key unwrap. |
| **High** | **Metadata Leakage & Tampering** | Bypassing blind cloud directory salt obfuscation, forged ML-DSA-65 manifest acceptance, or Version 2 container checksum bypass. |
| **Medium** | **Decoy Vault & Local Isolation** | Duress passphrase detection, local privilege escalation, or non-deterministic seed generation flaws. |
| **Low / Info** | **Defensive Hardening** | Incomplete volatile memory zeroization (`fillZero`), non-critical timing discrepancies, or theoretical improvements. |

### Out of Scope

The following vectors are considered out of scope:

* Social engineering, phishing, or physical coercion targeting vault users.
* Physical hardware attacks requiring laboratory chip decapping or bus probing on jailbroken devices.
* Denial-of-service (DoS) against third-party cloud storage APIs.
* Vulnerabilities in upstream operating systems or JVM/Kotlin runtimes unless directly triggered by our implementation.

---

## ⏱️ Response Timeframes & SLAs

When you submit a vulnerability report, you can expect:

* **Initial Acknowledgment:** Within **24 to 48 hours** of receipt.
* **Triage & Assessment:** Within **72 hours**, confirming whether the issue is reproducible and assigning a severity rating.
* **Status Updates:** Regular updates every **3 to 5 business days** while a fix is being engineered and verified.
* **Patch Deployment:** Critical issues are prioritized for emergency release; standard patches are deployed within **14 to 30 days**.
* **Coordinated Disclosure:** We adhere to standard 90-day coordinated vulnerability disclosure guidelines. We will coordinate with you on the public disclosure date and advisory release.

---

## 🤝 Safe Harbor Policy

We consider security research conducted under this policy to be authorized, constructive, and valuable. We will **not** initiate legal action against researchers who:

1. Act in good faith to identify and report vulnerabilities.
2. Avoid accessing, viewing, modifying, or destroying user data.
3. Avoid degrading the performance or availability of production services.
4. Provide us reasonable time to remediate the vulnerability prior to public disclosure.
5. Comply with applicable laws and regulations in their jurisdiction.

---

## 🏆 Recognition & Acknowledgements

With your consent, researchers who responsibly discover and report verified security vulnerabilities will be publicly recognized and thanked in:

* The official GitHub Security Advisory release notes.
* The Sino Wall of Honor at [https://sinosecure.app/acknowledgements](https://sinosecure.app/acknowledgements).
* The Sino Security & Bug Bounty Hall of Fame at [https://sinosecure.app/security#bug-bounty](https://sinosecure.app/security#bug-bounty).

---

_Last Updated: September 2026_  
_© 2026 Sino Project. All Rights Reserved._
