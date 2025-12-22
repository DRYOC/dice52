# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.5] - 2024-12-21

### Added

#### Paranoid Mode (Section 7.2)
- **Configurable Security Levels**: New `ParanoidConfig` type for fine-tuning security parameters
- **Periodic Ko Re-enhancement**: Commit-reveal protocol can now run every N epochs for additional entropy injection
- **Configurable Epoch Limits**: `MaxMessagesPerEpoch` can be reduced from 33 to increase ratchet frequency
- **Defense Against Weak RNG**: Independent entropy from both parties protects against compromised random number generators

#### New Configuration Options
| Parameter | Description | Default |
|-----------|-------------|---------|
| `Enabled` | Activate paranoid mode | `true` |
| `KoReenhanceInterval` | Epochs between Ko re-enhancement (0 = never) | `10` |
| `MaxMessagesPerEpoch` | Messages before mandatory ratchet (1-33) | `16` |

#### Go API Additions
- `ParanoidConfig` struct with `Validate()` and `DefaultParanoidConfig()`
- `Session.SetParanoidMode(config)` - Enable paranoid mode
- `Session.GetParanoidConfig()` - Get current configuration
- `Session.IsParanoidMode()` - Check if paranoid mode is active
- `Session.NeedsKoReenhancement()` - Check if Ko re-enhancement is pending
- `Session.KoStartReenhancement()` - Start Ko re-enhancement after ratchet
- `Session.KoProcessReenhanceCommit()` - Process peer's re-enhancement commit
- `Session.KoFinalizeReenhancement()` - Finalize Ko re-enhancement

#### Rust API Additions
- `ParanoidConfig` struct with `new()`, `default()`, and `validate()`
- `Session::set_paranoid_mode(config)` - Enable paranoid mode
- `Session::get_paranoid_config()` - Get current configuration
- `Session::is_paranoid_mode()` - Check if paranoid mode is active
- `Session::needs_ko_reenhancement()` - Check if Ko re-enhancement is pending
- `Session::ko_start_reenhancement()` - Start Ko re-enhancement
- `Session::ko_process_reenhance_commit()` - Process peer's commit
- `Session::ko_finalize_reenhancement()` - Finalize re-enhancement
- `Dice52Error::ConfigError` - New error variant for configuration errors

### Changed

- `MaxMessagesPerEpoch` constant renamed to `DefaultMaxMessagesPerEpoch` (old name kept for compatibility)
- Session now tracks `lastKoEnhancedEpoch` for paranoid mode timing
- Ratchet function now checks for pending Ko re-enhancement

### Documentation

- RFC updated with Section 7.2 covering paranoid mode specification
- README updated with paranoid mode examples for both Go and Rust
- New configuration tables in documentation

### Security

- Ko re-enhancement uses separate AAD strings (`ko-reenhance-commit`, `ko-reenhance-reveal`) to distinguish from initial enhancement
- Shared secret from ratchet is stored only when paranoid mode requires it
- State is properly cleared after re-enhancement completes

---

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

[0.1.5]: https://github.com/dryoc/dice52/releases/tag/v0.1.5
[0.1.0]: https://github.com/dryoc/dice52/releases/tag/v0.1.0

