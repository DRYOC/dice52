# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2024-12-21

### Added

#### Core Protocol
- **Dice52-PQ Protocol**: Post-quantum authenticated ratcheting secure messaging protocol
- **RFC Specification**: Complete protocol specification in RFC-style document (`rfc-dice52-pq-protocol.md`)

#### Cryptographic Primitives
- **ML-KEM-768 (Kyber)**: Post-quantum key encapsulation mechanism
- **ML-DSA-65 (Dilithium mode3)**: Post-quantum digital signatures for authentication
- **HKDF-SHA-256**: Key derivation function for all key material
- **ChaCha20-Poly1305**: Authenticated encryption for message confidentiality

#### Key Features
- **Forward Secrecy**: Via KEM-based ratcheting mechanism
- **Post-Compromise Security**: Session recovery through ratchet updates
- **Quantum Resistance**: Protection against "harvest now, decrypt later" attacks
- **Per-Message Fresh Keys**: Unique encryption key for every message
- **Deterministic Key Ordering (Ko)**: Hidden ordering key influencing all derivations

#### Ko Enhancement Protocol
- **Commit-Reveal Phase**: Two-phase protocol for Ko enhancement
- **Independent Entropy**: Both parties contribute randomness to final Ko
- **Defense-in-Depth**: Protection against single-point-of-failure KEM compromise
- **Contribution Fairness**: Neither party can unilaterally bias the ordering key

#### Session Management
- **Authenticated Handshake**: Signed KEM encapsulation for session establishment
- **Chain Key Management**: Separate sending (`CKs`) and receiving (`CKr`) chains
- **Epoch-Based Rekeying**: 33-message limit per epoch with mandatory ratchet
- **Replay Protection**: Monotonic message counters and epoch verification

#### Go Implementation (`pkg/dice52/`)
- `types.go`: Constants and type definitions
- `kdf.go`: Key derivation functions (HKDF-based)
- `handshake.go`: Authenticated handshake protocol
- `crypto.go`: ChaCha20-Poly1305 encryption/decryption
- `session.go`: Session state management and Ko enhancement
- `ko_enhancement_test.go`: Test suite for Ko enhancement

#### Rust Implementation (`src/`)
- `lib.rs`: Library entry point and public API
- `types.rs`: Constants, types, and message structures
- `kdf.rs`: Key derivation functions
- `handshake.rs`: Handshake protocol implementation
- `crypto.rs`: AEAD encryption utilities
- `session.rs`: Session management with Ko enhancement
- `error.rs`: Error types and handling

#### Developer Tools
- **Go Demo**: `cmd/dice52/main.go` - Example usage
- **Rust Demo**: `src/bin/dice52.rs` - Example usage
- **Makefile**: Build targets for both Go and Rust
- **Benchmarks**: Rust benchmarks in `benches/benchmarks.rs`

#### Dependencies

**Go:**
- `github.com/cloudflare/circl` - Post-quantum cryptography (Kyber, Dilithium)
- `golang.org/x/crypto` - Cryptographic utilities

**Rust:**
- `pqcrypto-kyber` - ML-KEM implementation
- `pqcrypto-dilithium` - ML-DSA implementation
- `chacha20poly1305` - AEAD encryption
- `hkdf` / `sha2` - Key derivation
- `rand` - Secure random number generation

### Security

- All cryptographic operations use constant-time implementations where available
- Secret key material is designed for prompt erasure after use
- Commit verification uses constant-time comparison
- Sessions abort on any verification failure

---

[0.1.0]: https://github.com/dryoc/dice52/releases/tag/v0.1.0

