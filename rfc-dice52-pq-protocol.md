# Dice52-PQ Protocol Specification

### Version 1

## Status of This Memo

This document specifies the Dice52-PQ secure messaging protocol.
It is not an IETF standard, but is written in RFC style for review, analysis, and implementation consistency.

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

---

## 18. Conclusion

Dice52-PQ is a fully authenticated, post-quantum ratcheting secure messaging protocol that preserves Dice52's ordering-based key derivation while adhering to modern cryptographic best practices.

The Ko Enhancement Phase (Section 7.1) provides additional security by introducing independent entropy from both parties into the ordering key derivation, ensuring defense-in-depth against single-point-of-failure compromises.