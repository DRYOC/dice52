# Dice52-PQ Ratchet Protocol Specification

### Version 1 (Draft)

## Status of This Memo

⚠️ **EXPERIMENTAL** — This document specifies the Dice52-PQ secure messaging protocol as an **experimental research protocol**. It has not been formally analyzed, independently audited, or submitted to any standards body.

This specification is written in RFC style for review, analysis, and implementation consistency. It is **NOT** an IETF standard, Internet-Draft, or recommendation.

**Implementers and researchers are encouraged to:**
- Provide critical feedback
- Identify weaknesses in the design
- Suggest improvements or alternatives
- NOT deploy this in production systems

---

## 1. Introduction

Dice52-PQ is a **post-quantum authenticated ratcheting secure messaging protocol** designed to provide:

* Confidentiality
* Mutual authentication
* Forward secrecy
* Post-compromise security
* Resistance to quantum adversaries
* Deterministic but hidden key ordering

Dice52-PQ combines:

* **ML-KEM-768 (Kyber)** for key establishment and ratcheting
* **ML-DSA-65 (Dilithium mode3)** for authentication
* **HKDF-SHA-256** for key derivation
* **ChaCha20-Poly1305** for authenticated encryption

Dice52-PQ is inspired by modern double-ratchet designs but introduces an **Ordering Key (`Ko`)**, which deterministically and secretly influences all key derivations.

Dice52-PQ provides **computational security**, not information-theoretic (one-time-pad) security.

---

## 1.1 Scope and Non-Goals

### 1.1.1 What Dice52-PQ Is

Dice52-PQ is a **focused experiment** exploring:

* Post-quantum authenticated ratcheting using ML-KEM and ML-DSA
* The Ko (ordering key) concept for deterministic hidden key derivation
* Entropy-robust key agreement through commit-reveal enhancement
* Defense-in-depth against single-point cryptographic failures

### 1.1.2 What Dice52-PQ Is NOT

| Non-Goal | Rationale |
|----------|-----------|
| VPN or tunnel protocol | Dice52-PQ operates at the session layer; it does not handle IP routing, NAT traversal, or network-layer concerns. Use WireGuard, IPsec, or similar for those needs. |
| TLS replacement | TLS provides a complete, audited, standardized ecosystem. Dice52-PQ is a single cryptographic building block. |
| Signal Protocol replacement | Signal has formal proofs, extensive audits, and billions of users. Dice52-PQ is unproven. |
| Production-ready solution | No independent audit, no formal verification, no deployment experience. |
| Complete messaging system | Dice52-PQ provides key agreement and ratcheting only—not user identity, group messaging, metadata protection, or transport. |

### 1.1.3 Relationship to Existing Protocols

| Protocol | Relationship |
|----------|--------------|
| WireGuard | Dice52-PQ could theoretically operate as an inner ratchet layer within a WireGuard tunnel, but does NOT replace it. |
| Noise Framework | Dice52-PQ is **not** a Noise pattern. Future work may formalize a mapping to Noise-like semantics. |
| Signal Protocol | Dice52-PQ borrows conceptually from double-ratchet designs but introduces different primitives and the Ko concept. |
| MLS | Dice52-PQ is pairwise only; it does not address group key agreement. |

### 1.1.4 Security Caveats

This specification has NOT undergone:

* Formal symbolic analysis (e.g., ProVerif, Tamarin)
* Computational security proofs
* Independent cryptographic audit
* Side-channel analysis

Implementations MUST be considered experimental and SHOULD NOT be used where security failures could cause harm.

---

## 2. Notation and Conventions

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are to be interpreted as described in RFC 2119.

| Symbol          | Meaning                  |
| --------------- | ------------------------ |
| `HKDF()`        | HKDF using SHA-256       |
| `AEAD()`        | Authenticated encryption |
| `Encapsulate()` | ML-KEM encapsulation     |
| `Decapsulate()` | ML-KEM decapsulation     |

All byte concatenations are literal.

---

## 3. Cryptographic Primitives

### 3.1 Post-Quantum Asymmetric

| Purpose            | Algorithm                   |
| ------------------ | --------------------------- |
| Key Encapsulation  | ML-KEM-768 (Kyber)          |
| Digital Signatures | ML-DSA-65 (Dilithium mode3) |

### 3.2 Symmetric

| Purpose        | Algorithm         |
| -------------- | ----------------- |
| Key Derivation | HKDF-SHA-256      |
| Encryption     | ChaCha20-Poly1305 |
| Hash           | SHA-256           |

---

## 4. Long-Term Identity Keys

Each participant MUST possess:

* A long-term **Dilithium private signing key**
* A corresponding **Dilithium public verification key**

These keys are **out-of-band authenticated** (e.g., PKI, QR code, manual fingerprint verification).

The signature context string:

```
"Dice52-PQ-Signature"
```

MUST be prepended to all signed data.

---

## 5. Session State

Each session maintains the following state:

| Name        | Description                     |
| ----------- | ------------------------------- |
| `RK`        | Root Key                        |
| `Ko`        | Ordering Key                    |
| `CKs`       | Sending Chain Key               |
| `CKr`       | Receiving Chain Key             |
| `Ns`        | Sending message counter         |
| `Nr`        | Receiving message counter       |
| `Epoch`     | Rekey epoch counter             |
| `SessionID` | Fixed 32-bit session identifier |

All cryptographic secrets MUST be erased as soon as they are no longer needed.

---

## 6. Authenticated Initial Handshake

### 6.1 Purpose

The initial handshake establishes:

* Mutual authentication
* An initial shared secret `SS₀`
* Initial values for `RK`, `Ko`, `CKs`, and `CKr`

### 6.2 Handshake Message (Alice → Bob)

Alice performs:

1. `Encapsulate(Bob_KEM_Public)` → `(CT, SS₀)`
2. Signs `SigContext || CT` using her Dilithium private key

She sends:

```
HandshakeMessage {
    KyberCT
    DilithiumSignature
}
```

### 6.3 Verification and Decapsulation (Bob)

Bob:

1. Verifies the Dilithium signature using Alice’s public key
2. Decapsulates `CT` → `SS₀`

If signature verification fails, the handshake MUST be aborted.

---

## 7. Root Key and Ordering Key Derivation

Both parties compute:

```
RK = HKDF(SS₀, "Dice52-RK")
Ko_base = HKDF(RK,  "Dice52-Ko")
```

`Ko_base` is the initial ordering key derived from the handshake. It MUST be enhanced
via the Ko Enhancement Phase (Section 7.1) before session use.

### 7.1 Ko Enhancement Phase (Commit-Reveal)

The Ko Enhancement Phase adds independent entropy from both parties to prevent
single-point-of-failure compromise. This phase MUST complete before any messages
are sent.

#### 7.1.1 Purpose

* Provides defense-in-depth: compromise of the primary KEM does not reveal Ko
* Ensures neither party can unilaterally bias the ordering key
* Adds independent randomness beyond the KEM shared secret

#### 7.1.2 Commit Phase

Both parties simultaneously:

1. Generate local entropy: `R_local = random(32 bytes)`
2. Compute commitment: `Commit = SHA-256("Dice52-Ko-Commit" || SessionID || R_local)`
3. Exchange commits encrypted with temporary key:
   ```
   TK = HKDF(SS₀, "Dice52-Ko-CommitKey")
   CommitMessage = AEAD_Encrypt(TK, nonce=0, Commit, AD="ko-commit")
   ```

#### 7.1.3 Reveal Phase

After both commits are received:

1. Exchange reveals: `RevealMessage = AEAD_Encrypt(TK, nonce=1, R_local, AD="ko-reveal")`
2. Verify peer's reveal matches their commit:
   ```
   Expected = SHA-256("Dice52-Ko-Commit" || SessionID || R_peer)
   if Expected != Commit_peer: ABORT
   ```

#### 7.1.4 Ko Finalization

Both parties compute enhanced Ko:

```
Ko = HKDF(Ko_base || R_initiator || R_responder, "Dice52-Ko-Enhanced")
```

Where:
* `R_initiator` is the initiator's (Alice's) entropy
* `R_responder` is the responder's (Bob's) entropy
* Order is fixed regardless of which party computes

The enhanced `Ko` MUST remain secret and MUST NOT be transmitted.

### 7.2 Paranoid Mode (Optional)

Paranoid mode provides additional security guarantees through:
* Periodic Ko re-enhancement using commit-reveal
* Reduced epoch message limits

#### 7.2.1 Configuration

Paranoid mode is configured with the following parameters:

| Parameter | Description | Default |
| --------- | ----------- | ------- |
| `enabled` | Whether paranoid mode is active | false |
| `ko_reenhance_interval` | Epochs between Ko re-enhancement (0 = never) | 10 |
| `max_messages_per_epoch` | Override for the 33-message limit (1-33) | 16 |

#### 7.2.2 Ko Re-enhancement

When paranoid mode is enabled with `ko_reenhance_interval > 0`:

1. After each ratchet, check if `(current_epoch - last_ko_enhanced_epoch) >= ko_reenhance_interval`
2. If true, flag the session for Ko re-enhancement
3. Before sending new messages, both parties MUST complete a new commit-reveal:

```
TK = HKDF(SS_ratchet, "Dice52-Ko-CommitKey")
ReenhanceCommit = AEAD_Encrypt(TK, nonce=0, Commit, AD="ko-reenhance-commit")
ReenhanceReveal = AEAD_Encrypt(TK, nonce=1, R_local, AD="ko-reenhance-reveal")
Ko = HKDF(Ko || R_initiator || R_responder, "Dice52-Ko-Enhanced")
```

#### 7.2.3 Reduced Epoch Limits

When `max_messages_per_epoch` is configured:
* The epoch message limit is reduced from 33 to the configured value
* This increases ratchet frequency, improving forward secrecy granularity
* Value MUST be between 1 and 33 inclusive

#### 7.2.4 Security Considerations

Paranoid mode provides:
* **Weak RNG mitigation**: If one party's RNG is weak during a ratchet, the other party's entropy protects Ko
* **Faster key rotation**: More frequent ratchets limit exposure from any single key
* **Defense-in-depth**: Multiple independent entropy sources throughout session lifetime

Trade-offs:
* **Latency**: 2 additional round-trips per Ko re-enhancement
* **Complexity**: More protocol state to manage

---

## 8. Chain Key Initialization

```
CKs = HKDF(RK, "Dice52-CKs" || Ko)
CKr = HKDF(RK, "Dice52-CKr" || Ko)
Ns  = 0
Nr  = 0
Epoch = 0
```

---

## 9. Message Key Derivation

For message number `n` and direction `dir`:

```
CK_next || MK = HKDF(
    IKM = CK,
    salt = RK,
    info = "Dice52-MK" || Ko || dir || n
)
```

* `MK` MUST be used exactly once
* `CK` MUST be replaced by `CK_next`
* `MK` MUST be erased after use

---

## 10. Message Encryption

### 10.1 Associated Data

The AEAD associated data MUST include:

* Protocol version
* Epoch number
* Message number
* Direction

### 10.2 Nonce Construction

Nonce is 96 bits:

```
nonce = SessionID || Epoch || MessageCounter
```

### 10.3 Encryption

```
ciphertext = AEAD_Encrypt(
    key = MK,
    nonce,
    plaintext,
    AD
)
```

---

## 11. Message Decryption

Upon receipt:

1. Verify epoch equality
2. Reject replayed message numbers
3. Derive `MK` using `CKr`
4. Decrypt using AEAD
5. On failure, discard message

---

## 12. Post-Quantum Ratchet

### 12.1 Purpose

The ratchet provides:

* Forward secrecy
* Post-compromise security

### 12.2 Ratchet Initiation (Signed)

Initiator:

1. Generates new Kyber key pair
2. Signs `SigContext || KyberPublicKey`
3. Sends:

```
RatchetMessage {
    KyberPublicKey
    DilithiumSignature
}
```

### 12.3 Ratchet Response

Responder:

1. Verifies signature
2. Encapsulates → `(CT, SSᵣ)`
3. Updates keys
4. Sends `CT`

### 12.4 Ratchet Finalization

Initiator:

1. Decapsulates `CT` → `SSᵣ`
2. Updates keys

### 12.5 Ratchet Key Update

Both sides compute:

```
RK = HKDF(RK || SSᵣ || Ko, "Dice52-RK-Ratchet")
Ko = HKDF(RK, "Dice52-Ko")
CKs, CKr = reinitialized
Epoch++
Ns = 0
Nr = 0
```

---

## 13. Epoch and the 33-Message Rule

Each epoch MUST allow **at most 33 messages**.

When exhausted:

* A ratchet or new handshake MUST occur
* Continued use without rekeying is forbidden

This limit bounds cryptanalytic exposure.

---

## 14. Replay Protection

* Message numbers MUST be monotonically increasing
* Messages with lower counters MUST be rejected
* Epoch mismatches MUST be rejected

---

## 15. Security Properties

Dice52-PQ provides:

| Property                       | Status |
| ------------------------------ | ------ |
| Confidentiality                | Yes    |
| Authentication                 | Yes    |
| Forward Secrecy                | Yes    |
| Post-Compromise Security       | Yes    |
| Quantum Resistance             | Yes    |
| Information-Theoretic Security | No     |

---

## 16. Limitations

* Security depends on ML-KEM and ML-DSA assumptions
* No deniability guarantees
* Implementations MUST use constant-time cryptography

## 16.1 Ko Enhancement Security Considerations

The Ko Enhancement Phase (Section 7.1) provides:

* **Defense-in-depth**: Compromise of the primary KEM shared secret does not reveal the enhanced Ko
* **Contribution fairness**: Neither party can unilaterally bias Ko due to commit-reveal
* **Independent entropy**: Ko incorporates randomness beyond the KEM encapsulation

Implementations MUST:
* Use cryptographically secure random number generators for entropy
* Complete the enhancement phase before sending any application messages
* Abort the session if commit verification fails
* Use constant-time comparison for commit verification

---

## 17. References

* NIST FIPS 203 — ML-KEM
* NIST FIPS 204 — ML-DSA
* RFC 5869 — HKDF
* RFC 8439 — ChaCha20-Poly1305
* Goldwasser, S. and Micali, S. (1982) — "Probabilistic Encryption & How To Play Mental Poker Keeping Secret All Partial Information," Proceedings of the 14th Annual ACM Symposium on Theory of Computing (STOC '82)

---

## 18. Conclusion

Dice52-PQ is an **experimental** post-quantum ratcheting protocol that explores entropy-robust key derivation through the Ko (ordering key) concept. It combines ML-KEM and ML-DSA with a commit-reveal enhancement phase to provide defense-in-depth against cryptographic failures.

The Ko Enhancement Phase (Section 7.1) provides additional security by introducing independent entropy from both parties into the ordering key derivation, ensuring defense-in-depth against single-point-of-failure compromises.

### 18.1 Future Work

For Dice52-PQ to mature beyond experimental status, the following would be required:

* Formal symbolic analysis (ProVerif, Tamarin) to verify security properties
* Computational security proofs under standard assumptions
* Independent cryptographic audit by qualified reviewers
* Side-channel analysis and implementation hardening
* Community review and feedback from CFRG or equivalent

### 18.2 Call for Review

The authors invite critical feedback on this specification. Weaknesses, alternative designs, and constructive criticism are welcomed. Please avoid deploying this protocol in production systems until it has undergone rigorous independent review.