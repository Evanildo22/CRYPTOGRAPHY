# Threat Model — Secure File Share

> **Reading guide for reviewers:** This document follows a structured threat-modelling methodology: assets → adversaries → attack trees → mitigations → residual risks → explicit non-goals. Limitations are stated honestly rather than glossed over. A system with documented residual risks is more trustworthy than one that claims to have none.

---

## 1. System Description

Secure File Share is a web application that encrypts files before storage, signs ciphertext to bind uploader identity, and records every security-relevant event in a tamper-evident audit log. It supports two encryption modes:

- **Mode A — RSA Key Transport:** A random 256-bit AES session key is wrapped with the recipient's RSA-2048 public key (OAEP). Only the matching private key can unwrap it.
- **Mode B — ECDH + PFS:** An ephemeral P-256 keypair is generated per upload; ECDH + HKDF derive the AES session key; the ephemeral private key is immediately destroyed and never written to disk. Compromise of the recipient's long-term key cannot expose past sessions.

**Trust boundaries:**

```
┌─────────────────────────────────────────────────────────────────┐
│  CLIENT BROWSER (untrusted)                                      │
│  • User pastes private keys into form fields                     │
│  • Keys are transmitted over the network to the server           │
└──────────────────────────────┬──────────────────────────────────┘
                               │  HTTPS (required; not enforced by app)
┌──────────────────────────────▼──────────────────────────────────┐
│  FLASK APPLICATION SERVER (semi-trusted)                         │
│  • Receives and processes keys + file data in memory             │
│  • Persists only ciphertext, wrapped keys, signatures, digests   │
│  • Never stores private keys                                     │
└──────────────────────────────┬──────────────────────────────────┘
                               │  Local filesystem
┌──────────────────────────────▼──────────────────────────────────┐
│  STORAGE (untrusted — assume attacker can read)                  │
│  storage/files/*.enc   storage/keys/*.key   storage/sigs/*.sig   │
│  storage/fingerprints/*.sha256   storage/audit/audit.log         │
└─────────────────────────────────────────────────────────────────┘
```

Key architectural decision: the design assumes the storage layer is compromised. Files must remain confidential and signatures must remain verifiable under that assumption. Private keys are never stored server-side.

---

## 2. Assets

What this system is trying to protect, why it has value, and what happens if it is lost.

| Asset | Sensitivity | Location | Impact if Compromised |
|---|---|---|---|
| **File plaintext** | Critical | RAM only; never persisted unencrypted | Direct data breach — primary objective of any attacker |
| **AES session key** | Critical | RAM; persisted only as RSA-wrapped (Mode A) or ECDH-derived (Mode B) | Enables decryption of the associated file |
| **RSA private key (recipient)** | Critical | Client-side only — never sent to server | Mode A: enables decryption of all past + future wrapped files. Mode B: enables future decryption only (PFS protects past sessions) |
| **EC private key (recipient)** | Critical | Client-side only | Mode B: enables reproduction of ECDH for future sessions; past sessions protected by PFS |
| **RSA private key (signer)** | Critical | Client-side only | Enables forgery of upload signatures, breaking authenticity guarantee |
| **`AUDIT_LOG_KEY`** | High | Environment variable | Enables undetectable log tampering; attacker can forge valid HMACs for edited entries |
| **Ciphertext blobs (`.enc`)** | Medium | `storage/files/` | Confidentiality depends on session key secrecy; integrity already protected by GCM tag |
| **Wrapped session keys (`.key`)** | High | `storage/keys/` | Required for Mode A decryption; useless without the RSA private key |
| **Ephemeral EC public keys (`.ecpub`)** | Low | `storage/keys/` | Public values — safe to expose by design; needed for recipient to reproduce ECDH |
| **Signatures (`.sig`)** | Medium | `storage/sigs/` | Deletion prevents integrity verification; forgery requires private key |
| **Plaintext fingerprints (`.sha256`)** | Low | `storage/fingerprints/` | SHA-256 is one-way — reveals only a hash of the file, not the file |
| **Audit log (`.log`)** | High | `storage/audit/` | Deletion or tampering destroys non-repudiation; detected by HMAC re-verification |

---

## 3. Adversary Model

Each adversary is characterised by their **access level**, **goals**, and **assumed resources**. Overstating adversary capability produces useless mitigations; understating it produces false confidence.

### ADV-1 — Passive Network Observer

**Who:** ISP, backbone router operator, coffee-shop Wi-Fi sniff, cloud provider packet capture.

**Access:** Can read all traffic between client and server. Cannot modify it.

**Resources:** Standard traffic analysis tooling. No cryptanalytic capability beyond what is publicly feasible.

**Goal:** Recover file plaintext from observed ciphertext.

**Assumed knowledge:** Knows the application protocol, algorithm choices, and all public keys. Does not know private keys or session keys. (Kerckhoffs's principle: security must not depend on secrecy of the algorithm.)

---

### ADV-2 — Active Network Attacker (MitM)

**Who:** Router under attacker control, rogue DNS, BGP hijack, evil proxy.

**Access:** Can read, modify, inject, and replay traffic. Cannot break TLS if correctly deployed.

**Resources:** Full control of the network path. No access to server filesystem.

**Goal:** Replace a legitimate ciphertext with attacker-controlled content that passes verification; or replay a stale ciphertext from a previous upload.

---

### ADV-3 — Storage-Level Attacker

**Who:** Cloud storage breach, misconfigured S3 bucket, compromised backup, rogue sysadmin with read-only filesystem access.

**Access:** Read access to the entire `storage/` directory. No access to application memory or environment variables.

**Resources:** Can read `.enc`, `.key`, `.sig`, `.sha256`, `.log` files freely. Has unlimited offline compute time.

**Goal:** Recover file plaintext; or determine which files were exchanged between which parties.

---

### ADV-4 — Compromised Server (Full RCE)

**Who:** Attacker who achieves Remote Code Execution on the Flask process — via web vulnerability, supply-chain compromise, or malicious dependency.

**Access:** Reads application memory, environment variables, process state. Can intercept keys at the moment they are submitted to the server.

**Resources:** Everything the server process can access. Cannot access client memory directly.

**Goal:** Steal private keys submitted in form fields; steal `AUDIT_LOG_KEY`; read plaintext from RAM during decryption.

---

### ADV-5 — Future Attacker (Retroactive Decryption)

**Who:** Any of the above who records encrypted traffic or storage now and waits.

**Scenario:** Attacker archives all `.enc` and `.key` files today. At some future point they obtain the recipient's long-term private key (device theft, legal compulsion, cryptanalytic break).

**Goal:** Decrypt all historically recorded sessions.

---

### ADV-6 — Malicious Insider / Audit Evader

**Who:** A legitimate user (uploader or downloader) who wants to perform an action and erase all record of it; or a server operator who wants to retroactively modify the audit log.

**Access:** Full access to `storage/audit/audit.log`. May also have `AUDIT_LOG_KEY` if they are the server operator.

**Goal:** Delete, modify, or suppress log entries without detection.

---

### ADV-7 — Offline Password Attacker

**Who:** Anyone who obtains the `.key` file and has GPU/ASIC compute resources.

**Access:** The wrapped AES session key file and the stored PBKDF2 salt. No access to the server.

**Goal:** Recover the user's password via brute force or dictionary attack, then rederive the KEK to unwrap the session key.

---

## 4. Attack Trees

An attack tree traces the steps an adversary would need to take to achieve their goal. Each leaf is an atomic capability; branches are AND (all required) or OR (any sufficient).

---

### AT-1 — Recover Plaintext (ADV-1: Passive Observer)

```
GOAL: Decrypt a file from observed network traffic
│
├── [OR] Obtain the AES session key
│   ├── [AND — Mode A] Observe the wrapped .key in transit
│   │   AND Obtain recipient RSA private key  ← requires separate attack (AT-5)
│   │
│   └── [AND — Mode B] Observe the .ecpub in transit
│       AND Obtain recipient EC private key   ← requires separate attack (AT-5)
│       AND Reconstruct HKDF (public algorithm, known inputs if you have the key)
│
└── [OR] Break AES-256-GCM directly
    └── Current academic best: 2^128 work to recover key — computationally infeasible
```

**Verdict:** Blocked at the session key step. Passive observation of ciphertext provides no path to plaintext without a private key compromise that is out of this adversary's capability.

---

### AT-2 — Inject a Forged File (ADV-2: Active MitM)

```
GOAL: Replace a legitimate upload with attacker-controlled content
│
├── [OR] Replace ciphertext in transit and produce a valid signature
│   ├── Forge an RSA-PSS signature without the private key
│   │   └── Requires solving the RSA problem — 2^112 classical hardness for 2048-bit
│   │
│   └── Obtain the uploader's RSA private key  ← separate attack (AT-5)
│
└── [OR] Replay a previous valid ciphertext + signature
    └── File IDs are UUIDs; a replayed file appears as a different file ID
        The recipient can detect this by comparing the expected file ID out-of-band
        ⚠ No nonce / sequence number is included in the signed data — replay within
          the same file ID slot is not explicitly prevented by the signature alone
```

**Verdict:** Active injection is blocked by RSA-PSS. Replay within a session is a residual risk noted below.

---

### AT-3 — Read Files from Storage (ADV-3: Storage Breach)

```
GOAL: Recover plaintext from storage/
│
├── Read .enc (ciphertext blob)
│   └── Cannot decrypt without session key (AES-256-GCM, 128-bit security)
│
├── [Mode A] Read .key (RSA-wrapped session key)
│   └── Cannot unwrap without recipient RSA private key  ← not in storage
│
├── [Mode B] Read .ecpub (ephemeral EC public key)
│   └── Cannot reproduce ECDH without:
│       ├── Ephemeral private key  ← destroyed; never persisted
│       └── Recipient EC private key  ← not in storage
│
└── Read .sha256 (SHA-256 fingerprint)
    └── SHA-256 is one-way — reveals only that two files are identical if they share
        a digest; does not recover plaintext
        ⚠ For low-entropy files (e.g. "yes" or "no"), a rainbow table over the
          SHA-256 of common values could confirm the plaintext — low practical risk
          for real files but worth noting
```

**Verdict:** Storage breach alone does not expose plaintext in either mode.

---

### AT-4 — Tamper with the Audit Log (ADV-6: Insider / Audit Evader)

```
GOAL: Modify a past log entry without detection
│
├── Edit an entry field (e.g. change event_type UPLOAD → DOWNLOAD)
│   └── Stored HMAC no longer matches recomputed HMAC
│       └── Audit viewer flags entry as TAMPERED
│
├── Replace the HMAC field with a newly computed HMAC
│   └── Requires AUDIT_LOG_KEY
│       ├── Key not in storage — must compromise environment variable
│       └── If server is fully compromised (ADV-4), key is accessible
│           ⚠ RESIDUAL RISK: full server compromise defeats log integrity
│
├── Delete entire log entries
│   └── Detected only if the log consumer tracks expected entry count
│       ⚠ RESIDUAL RISK: deletion of entries is not detected by HMAC alone
│         A production system would use a hash-chained log (each entry includes
│         hash of the previous entry) to make deletion detectable
│
└── Delete the log file entirely
    └── Detected — audit viewer reports "no entries" rather than entries
        ⚠ RESIDUAL RISK: indistinguishable from a never-used system;
          requires separate monitoring to detect unexpected log absence
```

**Verdict:** HMAC-SHA256 prevents silent field modification. Deletion and full-server-compromise are residual risks.

---

### AT-5 — Compromise a Private Key

```
GOAL: Obtain a user's RSA or EC private key
│
├── Extract from browser memory / clipboard after paste
│   └── Requires client-side malware or browser exploit — endpoint compromise
│
├── Intercept key in transit (form POST to /upload or /download)
│   ├── Over HTTP: trivial — key transmitted in plaintext
│   │   ⚠ APPLICATION DOES NOT ENFORCE HTTPS — deploy behind TLS proxy
│   └── Over HTTPS: requires MitM with cert forgery or CA compromise
│
├── Steal from server RAM during processing (ADV-4: RCE)
│   └── Flask processes key bytes during wrap/unwrap
│       → Attacker with RCE can read process memory
│       ⚠ RESIDUAL RISK: no HSM; keys pass through application memory
│
└── Social engineering / physical access to client device
    └── Out of scope for this system
```

---

### AT-6 — Retroactive Decryption After Key Compromise (ADV-5)

```
GOAL: Decrypt past sessions after obtaining long-term private key
│
├── Mode A — RSA Key Transport
│   ├── Obtain recipient RSA private key (AT-5)
│   └── Read .key file from storage
│       → AES session key recovered → plaintext decrypted
│       ⚠ NO FORWARD SECRECY IN MODE A — this attack fully succeeds
│
└── Mode B — ECDH + PFS
    ├── Obtain recipient EC private key (AT-5)
    └── Attempt ECDH with stored .ecpub
        ├── Ephemeral private key required for ECDH — destroyed at upload time
        └── ECDH is asymmetric: public + public ≠ shared secret
            → Cannot reproduce shared secret with only one side's private key
            ✓ FORWARD SECRECY HOLDS — past sessions cannot be decrypted
```

---

## 5. Mitigations and Their Limits

### Symmetric Encryption — AES-256-GCM

| Property | Detail |
|---|---|
| **What it provides** | Confidentiality + integrity (AEAD) in a single pass |
| **Key size** | 256-bit — 128-bit security margin against brute force |
| **IV** | 96-bit random per operation; GCM is optimal at this size |
| **Authentication tag** | 128-bit; prepended to blob for early-rejection on read |
| **Residual risk** | IV collision probability: ~2^{-32} after 2^{32} encryptions under the same key. Session keys are single-use — this limit is never approached. |
| **Known limitation** | Not post-quantum secure. Grover's algorithm reduces effective key strength to 128 bits on a quantum computer, which still meets NIST's post-quantum security level 1. Symmetric algorithms require only a key-size doubling to remain secure post-quantum. |

### Asymmetric Encryption — RSA-2048 OAEP

| Property | Detail |
|---|---|
| **What it provides** | Key transport: wraps the AES session key |
| **Padding** | OAEP with SHA-256 + MGF1 — IND-CCA2 secure under ROM |
| **Why not PKCS#1 v1.5** | Bleichenbacher 1998 adaptive CCA2 attack — completely broken for encryption |
| **Residual risk** | RSA-2048 provides ~112 bits of classical security. NIST estimates classical hardness holds through 2030. |
| **Known limitation** | **Not post-quantum secure.** Shor's algorithm breaks RSA in polynomial time on a sufficiently large quantum computer. Migration to CRYSTALS-Kyber (NIST PQC standard) would be required before quantum computers are practical. This is not a near-term concern but is a known architectural debt. |
| **Known limitation** | No PFS in Mode A. Compromise of the long-term private key retroactively exposes all Mode A sessions. |

### Key Exchange — ECDH P-256 + HKDF-SHA256

| Property | Detail |
|---|---|
| **What it provides** | Key agreement: both parties derive the same session key from a DH exchange |
| **Curve** | P-256 (NIST secp256r1) — ~128-bit classical security |
| **Post-ECDH processing** | HKDF-SHA256 with domain-separation label — raw ECDH output is a curve point, not uniformly random; HKDF extracts entropy and expands to a proper key |
| **Residual risk** | P-256 is a NIST curve with curve parameters generated by NSA. While no backdoor has ever been demonstrated, cryptographers who distrust NIST curves prefer X25519. This implementation chose P-256 for maximum library compatibility. |
| **Known limitation** | **Not post-quantum secure.** Shor's algorithm breaks ECDLP. NIST PQC replacement: CRYSTALS-Kyber for KEM. |

### Digital Signatures — RSA-PSS-SHA256

| Property | Detail |
|---|---|
| **What it provides** | Authenticity: binds uploader identity to the ciphertext |
| **What is signed** | The ciphertext (not plaintext) — covers exactly what is stored |
| **Salt length** | `PSS.MAX_LENGTH` (= hLen = 32 bytes for SHA-256) — maximum security margin |
| **Why not PKCS#1 v1.5 signing** | Known forgery vulnerabilities in certain configurations; PSS has a tight security proof |
| **Residual risk** | The signed message is the raw ciphertext bytes — there is no timestamp or file-ID binding in the signed payload. A valid signature can be detached and re-attached to the same ciphertext under a different file ID. |
| **Known limitation** | Not post-quantum secure (same RSA quantum vulnerability). NIST PQC replacement: CRYSTALS-Dilithium or FALCON. |

### Key Derivation — PBKDF2-HMAC-SHA256

| Property | Detail |
|---|---|
| **What it provides** | Derives a KEK from a user password; resists offline brute-force |
| **Iterations** | 600,000 — NIST SP 800-132 (2023) minimum for SHA-256 |
| **Salt** | 128-bit random, stored alongside key material |
| **Residual risk** | PBKDF2 is CPU-bound, not memory-hard. A GPU cluster can compute ~10^9 PBKDF2-SHA256 iterations/second (amortised). A 600k-iteration check takes ~0.6 ms on a GPU, yielding ~1.6M password checks/second. An 8-character lowercase-alpha password (~38 bits of entropy) falls in ~4 hours on a modern GPU. Users must choose strong passwords. |
| **Known limitation** | Argon2id (winner of the Password Hashing Competition, 2015) is strictly superior: it is memory-hard, making GPU/ASIC attacks ~1000× more expensive. This implementation uses PBKDF2 as the well-known baseline. A production system should use Argon2id. |

### Audit Log — HMAC-SHA256 Append-Only

| Property | Detail |
|---|---|
| **What it provides** | Tamper-evidence: modification of any field invalidates the stored HMAC |
| **Key** | 256-bit secret from environment variable — never stored in code |
| **Canonical form** | Sorted-key JSON, no extra whitespace — deterministic across platforms |
| **Residual risk** | HMAC detects modification of individual entries but does not detect deletion or reordering. A hash-chained log (each entry includes `H(previous_entry)`) would make deletion detectable at the cost of implementation complexity. |
| **Residual risk** | Full server compromise (`AUDIT_LOG_KEY` readable from env) enables undetectable forgery. Mitigation requires a write-only log shipped to a separate system (SIEM, append-only S3 bucket with bucket-level WORM policy). |

---

## 6. Security Properties Summary

| Property | Mode A | Mode B | Notes |
|---|---|---|---|
| Confidentiality | ✓ | ✓ | AES-256-GCM; requires session key to break |
| Ciphertext integrity | ✓ | ✓ | GCM 128-bit auth tag; tamper raises InvalidTag |
| Authenticity | ✓ | ✓ | RSA-PSS signature verified before decryption |
| Perfect forward secrecy | ✗ | ✓ | Mode A: long-term key compromise exposes all past sessions |
| Key compromise isolation | ✗ | ✓ | Mode B only: past sessions safe after key theft |
| Non-repudiation (log) | ✓ | ✓ | HMAC-SHA256; requires AUDIT_LOG_KEY to forge |
| Post-quantum confidentiality | ✗ | ✗ | Both modes broken by Shor's algorithm |
| Post-quantum signatures | ✗ | ✗ | RSA-PSS broken by Shor's algorithm |

---

## 7. What This System Does NOT Protect Against

These are explicit non-goals. A professional system acknowledges its scope rather than implying universal protection.

### Endpoint Compromise
If the client device running the browser is compromised (keylogger, malware, browser exploit), an attacker can read private keys directly from memory or intercept them before they are submitted to the server. This system has no visibility into client-side security. **All cryptographic guarantees collapse under endpoint compromise.**

### Server-Side Key Interception (No HSM)
Private keys are submitted to the server as form field values. They exist in Flask request memory during processing. An attacker with RCE on the server process can read them at the moment they are submitted. A production system would use a Hardware Security Module (HSM) to ensure private keys never exist in plaintext outside of tamper-resistant hardware.

### Metadata Leakage
The system does not conceal:
- **File size:** Ciphertext length ≈ plaintext length. An observer who knows typical file sizes can infer file type or content category.
- **Timing:** Upload/download timestamps are logged. Timing correlation can link senders and receivers even without reading content.
- **File IDs:** UUIDs are unpredictable but are exposed in URLs. Anyone who learns a file ID can attempt to download the file.
- **Access patterns:** The audit log records which IPs accessed which files. An attacker with audit log access learns the communication graph.

This system provides **content confidentiality**, not **traffic confidentiality**. For metadata protection, see: Tor hidden services, mixnets, or Private Information Retrieval schemes.

### Insider Threat (Malicious Server Operator)
The server operator can:
- Read all submitted private keys from process memory or logs if debug mode is enabled
- Read all plaintext during decryption (it passes through application memory)
- Modify or delete audit log entries if they have `AUDIT_LOG_KEY`
- Enumerate all stored files

The threat model assumes the server operator is honest. A design that does not trust the server would require client-side encryption (end-to-end, e.g. Keybase-style) where the server never sees plaintext or private keys.

### Denial of Service
No rate limiting is implemented. An attacker can:
- Flood `/upload` to consume disk space
- Flood `/keys` to exhaust CPU via RSA key generation
- Flood `/download` with decryption requests

This is a known gap. Production deployment requires a reverse proxy (nginx, Caddy) with request rate limiting.

### Supply Chain Attacks
Dependencies are pinned by version in `requirements.txt`. Pinning prevents silent upgrades that introduce vulnerabilities. It does not protect against:
- A malicious release of a pinned version (e.g. `cryptography==42.0.5` being replaced by a backdoored binary on PyPI after pin)
- Compromise of the build environment that installs dependencies

Mitigation in production: pin by hash (`pip install --require-hashes`), use a private mirror, and verify SLSA provenance attestations.

### Post-Quantum Adversaries
All asymmetric operations in this system — RSA-OAEP, RSA-PSS, ECDH P-256 — are broken by Shor's algorithm on a cryptographically relevant quantum computer (CRQC). As of 2024, no CRQC exists, but NIST has finalised post-quantum standards (FIPS 203 CRYSTALS-Kyber for KEM, FIPS 204 CRYSTALS-Dilithium for signatures). A "harvest now, decrypt later" adversary who archives today's traffic for future quantum decryption is a realistic threat for data with a 10+ year secrecy horizon.

**This system makes no post-quantum security claims.**

---

## 8. Assumptions

This model is valid only while the following hold:

1. **TLS is deployed.** The application does not enforce HTTPS. Running it over HTTP exposes private keys, session keys, and plaintext to any passive observer on the network path.
2. **`AUDIT_LOG_KEY` is secret.** If this key is exposed, the audit log can be silently forged.
3. **Users choose strong passwords.** PBKDF2 at 600k iterations buys time, not certainty. A weak password (< 60 bits entropy) falls to GPU brute force.
4. **The server process is not compromised.** RCE on the Flask process gives an attacker access to everything in memory.
5. **Client devices are not compromised.** Private keys pasted into the browser are readable by any malware running on that device.
6. **Quantum computers cannot break 128-bit symmetric keys in reasonable time.** The symmetric layer (AES-256-GCM) retains 128-bit post-quantum security. The asymmetric layer does not.

---

## 9. Future Hardening (Prioritised)

| Priority | Change | Threat Addressed |
|---|---|---|
| P0 | Deploy behind TLS (nginx/Caddy) | AT-1, AT-2, AT-5 transit interception |
| P0 | Replace PBKDF2 with Argon2id | AT-7 GPU brute force |
| P1 | Hash-chain audit log entries | AT-4 entry deletion undetected |
| P1 | Ship audit log to external append-only store | AT-4 full server compromise |
| P1 | Add file-ID and timestamp to RSA-PSS signed payload | AT-2 signature detachment |
| P2 | Add `--require-hashes` to pip install | Supply chain |
| P2 | Migrate asymmetric operations to CRYSTALS-Kyber + Dilithium | Post-quantum |
| P3 | Move to HSM or KMS for key operations | AT-5 server memory interception |
| P3 | Implement client-side encryption (E2E) | Insider threat, server compromise |
