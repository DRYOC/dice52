# Dice52-PQ Ratchet Protocol

![Logo](./logo/dice52-logo.png)

> ⚠️ **EXPERIMENTAL PROTOCOL** — Dice52-PQ is an experimental research protocol. It has not been audited, formally verified, or standardized. Do not use in production systems without independent security review.

Dice52 explores **entropy-robust post-quantum ratcheting** for secure channels. It is a key agreement protocol that uses **hybrid KEM** (ML-KEM/Kyber + X25519), ML-DSA (Dilithium) signatures to achieve quantum-resistant authenticated key exchange with classical security as a defense-in-depth.

**Goal:** A post-quantum, authenticated, forward-secret, per-message-key encryption protocol that preserves Dice52's Ko ordering concept.

**Hybrid KEM:** The shared secret remains secure provided at least one of the component KEMs (Kyber or X25519) remains secure. This follows the industry-standard approach used in TLS 1.3 hybrids, Signal PQ experiments, and OpenSSH PQ mode.

--------------------------------

**Available in:**
- [Go](./clients/golang/) ([example](./clients/golang/cmd/dice52/main.go))
- [Rust](./clients/rust/) ([example](./clients/rust/src/bin/dice52.rs))
- [Python 3](./clients/python3/) ([example](./clients/python3/dice52/demo.py))
- [Java](./clients/java/) ([example](./clients/java/src/main/java/io/dice52/Demo.java))

--------------------------------

## Status

| Aspect | Status |
|--------|--------|
| Specification | Draft v1 — subject to breaking changes |
| Implementation | Reference quality — not production-hardened |
| Security Audit | **None** — awaiting independent review |
| Formal Analysis | **None** — symbolic/computational proofs pending |
| Standardization | Not submitted to any standards body |

---

## Non-Goals

Dice52 is explicitly **NOT**:

| ❌ Non-Goal | Explanation |
|------------|-------------|
| A VPN replacement | Dice52 is not WireGuard, OpenVPN, or IPsec. It does not handle routing, tunneling, or network-layer concerns. |
| A TLS replacement | Dice52 focuses on ratcheted messaging, not the full TLS handshake/record layer ecosystem. |
| A Signal replacement | While inspired by double-ratchet designs, Dice52 lacks the ecosystem, formal proofs, and battle-testing of Signal. |
| Production-ready | No security audit, no formal verification, no production deployments. |
| A complete messaging system | Dice52 is a cryptographic primitive layer, not a full application protocol. |


## Design Principles:

### Adversary assumptions

 - Can record all traffic forever ("harvest now, decrypt later")
 - Can inject, replay, and modify packets
 - May eventually possess a large-scale quantum computer
 - May compromise a party's device at some point (post-compromise recovery needed)

### Security goals

 - Confidentiality
 - Authentication
 - Forward secrecy
 - Post-compromise security
 - Quantum resistance
 - Deterministic but hidden key ordering (Ko)
 - Per-message fresh keys
 - **Ko Enhancement**: Independent entropy contribution from both parties (defense-in-depth)


### Foundation:
Replace | With
---------|---------
X25519 only | **Hybrid KEM** (ML-KEM/Kyber + X25519)
Ed25519 | ML-DSA (Dilithium)
DH ratchet | Hybrid KEM ratchet

The hybrid KEM ensures security even if either Kyber or X25519 is broken individually.

### Dice52-PQ Ratchet RFC Specification:

[RFC Dice52-PQ Ratchet Protocol Specification](./rfc-dice52-pq-protocol.md)

---

## Ko Enhancement Protocol

The Ko Enhancement Phase (Section 7.1 of the RFC) provides additional security by introducing independent entropy from both parties into the ordering key derivation.

### Why Ko Enhancement?

| Without Enhancement | With Enhancement |
|---------------------|------------------|
| Ko derived solely from KEM shared secret | Ko includes entropy from both parties |
| Single point of failure (KEM compromise) | Defense-in-depth (need to compromise both) |
| Deterministic from handshake | Includes fresh randomness per session |

### Protocol Flow

```
Alice (Initiator)                    Bob (Responder)
     |                                    |
     |--- KoCommitMessage (encrypted) --->|
     |<--- KoCommitMessage (encrypted) ---|
     |                                    |
     |--- KoRevealMessage (encrypted) --->|
     |<--- KoRevealMessage (encrypted) ---|
     |                                    |
     | [verify commit, derive enhanced Ko]|
     |                                    |
     |=== Session ready with enhanced Ko ==|
```

The enhanced Ko is computed as:
```
Ko = HKDF(Ko_base || R_alice || R_bob, "Dice52-Ko-Enhanced")
```

---

## Paranoid Mode (Section 7.2)

Paranoid mode provides additional security guarantees for high-security applications:

| Feature | Standard Mode | Paranoid Mode |
|---------|---------------|---------------|
| Ko Enhancement | Once at session start | Periodic re-enhancement every N epochs |
| Messages per epoch | 33 | Configurable (1-33, default 16) |
| Ratchet frequency | Every 33 messages | More frequent |
| Latency | Lower | Higher (extra round-trips) |

### Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `Enabled` | Activate paranoid mode | `true` |
| `KoReenhanceInterval` | Epochs between Ko re-enhancement | `10` |
| `MaxMessagesPerEpoch` | Messages before mandatory ratchet | `16` |

### Go Example

```go
// Enable paranoid mode with default settings
alice.SetParanoidMode(dice52.DefaultParanoidConfig())

// Or customize the configuration
config := dice52.ParanoidConfig{
    Enabled:             true,
    KoReenhanceInterval: 5,   // Re-enhance Ko every 5 epochs
    MaxMessagesPerEpoch: 10,  // Ratchet every 10 messages
}
alice.SetParanoidMode(config)

// After ratchet, check if Ko re-enhancement is needed
if alice.NeedsKoReenhancement() {
    aliceCommit, _ := alice.KoStartReenhancement()
    bobCommit, _ := bob.KoStartReenhancement()
    
    aliceReveal, _ := alice.KoProcessReenhanceCommit(bobCommit)
    bobReveal, _ := bob.KoProcessReenhanceCommit(aliceCommit)
    
    alice.KoFinalizeReenhancement(bobReveal)
    bob.KoFinalizeReenhancement(aliceReveal)
}
```

### Rust Example

```rust
use dice52::ParanoidConfig;

// Enable paranoid mode with default settings
alice.set_paranoid_mode(ParanoidConfig::new())?;

// Or customize the configuration
let config = ParanoidConfig {
    enabled: true,
    ko_reenhance_interval: 5,   // Re-enhance Ko every 5 epochs
    max_messages_per_epoch: 10, // Ratchet every 10 messages
};
alice.set_paranoid_mode(config)?;

// After ratchet, check if Ko re-enhancement is needed
if alice.needs_ko_reenhancement() {
    let alice_commit = alice.ko_start_reenhancement()?;
    let bob_commit = bob.ko_start_reenhancement()?;
    
    let alice_reveal = alice.ko_process_reenhance_commit(&bob_commit)?;
    let bob_reveal = bob.ko_process_reenhance_commit(&alice_commit)?;
    
    alice.ko_finalize_reenhancement(&bob_reveal)?;
    bob.ko_finalize_reenhancement(&alice_reveal)?;
}
```

---

## Go Library

### Installation

```bash
go get github.com/dryoc/dice52
```

### Usage

Import the package in your Go code:

```go
import "github.com/dryoc/dice52/clients/golang/pkg/dice52"
```

#### Example: Establishing a Session with Hybrid KEM

```go
package main

import (
	"crypto/rand"
	"fmt"

	"github.com/dryoc/dice52/clients/golang/pkg/dice52"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

func main() {
	// Generate Kyber KEM key pairs for Alice and Bob
	pubA, privA, _ := kyber768.Scheme().GenerateKeyPair()
	pubB, privB, _ := kyber768.Scheme().GenerateKeyPair()

	kemPubA := pubA.(*kyber768.PublicKey)
	kemPrivA := privA.(*kyber768.PrivateKey)
	kemPubB := pubB.(*kyber768.PublicKey)
	kemPrivB := privB.(*kyber768.PrivateKey)

	// Generate X25519 key pairs for Alice and Bob (hybrid KEM)
	ecdhPubA, ecdhPrivA, _ := dice52.GenerateX25519Keypair()
	ecdhPubB, ecdhPrivB, _ := dice52.GenerateX25519Keypair()

	// Generate Dilithium identity key pairs
	idPubA, idPrivA, _ := mode3.GenerateKey(rand.Reader)
	idPubB, idPrivB, _ := mode3.GenerateKey(rand.Reader)

	// Alice performs hybrid encapsulation to Bob's public keys (Kyber + X25519)
	result, _ := dice52.InitiatorHybridEncapsulate(kemPubB, ecdhPubB)
	ssAlice := result.SSHybrid

	// Bob performs hybrid decapsulation using his private keys
	ssBob, _ := dice52.ResponderHybridDecapsulate(kemPrivB, ecdhPrivB, result.KyberCT, result.ECDHPub)

	// Derive initial keys (uses hybrid shared secret internally)
	rkAlice, koAlice := dice52.DeriveInitialKeys(ssAlice)
	rkBob, koBob := dice52.DeriveInitialKeys(ssBob)

	// Initialize chain keys
	cksAlice, ckrAlice := dice52.InitChainKeys(rkAlice, koAlice)
	cksBob, ckrBob := dice52.InitChainKeys(rkBob, koBob)

	// Create sessions with X25519 keys for future ratchets
	alice := &dice52.Session{
		SessionID: 1,
		RK:        rkAlice,
		Ko:        koAlice,
		CKs:       cksAlice,
		CKr:       ckrAlice,
		KEMPub:    kemPubA,
		KEMPriv:   kemPrivA,
		ECDHPub:   ecdhPubA,
		ECDHPriv:  ecdhPrivA,
		PeerECDHPub: ecdhPubB,
		IDPriv:    idPrivA,
		IDPub:     idPubA,
		PeerID:    idPubB,
	}

	bob := &dice52.Session{
		SessionID: 1,
		RK:        rkBob,
		Ko:        koBob,
		CKs:       ckrBob, // Bob's send = Alice's receive
		CKr:       cksBob, // Bob's receive = Alice's send
		KEMPub:    kemPubB,
		KEMPriv:   kemPrivB,
		ECDHPub:   ecdhPubB,
		ECDHPriv:  ecdhPrivB,
		PeerECDHPub: ecdhPubA,
		IDPriv:    idPrivB,
		IDPub:     idPubB,
		PeerID:    idPubA,
	}

	// Ko Enhancement: Add independent entropy from both parties
	// This provides defense-in-depth against KEM compromise
	alice.SetInitiator(true)
	bob.SetInitiator(false)
	
	// Phase 1: Exchange commitments
	aliceCommit, _ := alice.KoStartEnhancement(ssAlice)
	bobCommit, _ := bob.KoStartEnhancement(ssBob)
	
	// Phase 2: Exchange reveals
	aliceReveal, _ := alice.KoProcessCommit(bobCommit)
	bobReveal, _ := bob.KoProcessCommit(aliceCommit)
	
	// Phase 3: Finalize enhanced Ko
	alice.KoFinalize(bobReveal)
	bob.KoFinalize(aliceReveal)

	// Send encrypted message
	msg, _ := alice.Send([]byte("Quantum-safe hello"))
	pt, _ := bob.Receive(msg)
	fmt.Println(string(pt)) // "Quantum-safe hello"
}
```

### Running the Go Demo

```bash
make run
# or directly:
cd clients/golang && go run ./cmd/dice52
```

### Building Go

```bash
make build
# or directly:
cd clients/golang && go build ./...
```

---

## Rust Crate

### Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
dice52 = { git = "https://github.com/dryoc/dice52", subdirectory = "clients/rust" }
```

Or if published to crates.io:

```toml
[dependencies]
dice52 = "0.1"
```

### Usage with Hybrid KEM

```rust
use dice52::{
    Session, derive_initial_keys, init_chain_keys,
    generate_kem_keypair, generate_signing_keypair, generate_x25519_keypair,
    initiator_hybrid_encapsulate, responder_hybrid_decapsulate,
};

fn main() {
    // Generate Kyber KEM key pairs for Alice and Bob
    let (kem_pub_a, kem_priv_a) = generate_kem_keypair();
    let (kem_pub_b, kem_priv_b) = generate_kem_keypair();

    // Generate X25519 key pairs for Alice and Bob (hybrid KEM)
    let (ecdh_pub_a, ecdh_priv_a) = generate_x25519_keypair();
    let (ecdh_pub_b, ecdh_priv_b) = generate_x25519_keypair();

    // Generate Dilithium identity key pairs
    let (id_pub_a, id_priv_a) = generate_signing_keypair();
    let (id_pub_b, id_priv_b) = generate_signing_keypair();

    // Alice performs hybrid encapsulation to Bob's public keys (Kyber + X25519)
    let result = initiator_hybrid_encapsulate(&kem_pub_b, &ecdh_pub_b).unwrap();
    let ss_alice = result.ss_hybrid.clone();

    // Bob performs hybrid decapsulation using his private keys
    let ss_bob = responder_hybrid_decapsulate(
        &kem_priv_b,
        &ecdh_priv_b,
        &result.kyber_ct,
        &result.ecdh_pub
    ).unwrap();

    // Derive initial keys (uses hybrid shared secret internally)
    let (rk_alice, ko_alice) = derive_initial_keys(&ss_alice);
    let (rk_bob, ko_bob) = derive_initial_keys(&ss_bob);

    // Initialize chain keys
    let (cks_alice, ckr_alice) = init_chain_keys(&rk_alice, &ko_alice);
    let (cks_bob, ckr_bob) = init_chain_keys(&rk_bob, &ko_bob);

    // Create sessions with X25519 keys for future hybrid ratchets
    let alice = Session::new_with_ecdh(
        1,
        rk_alice,
        ko_alice,
        cks_alice,
        ckr_alice,
        kem_pub_a,
        kem_priv_a,
        ecdh_pub_a,
        ecdh_priv_a,
        ecdh_pub_b.clone(), // Peer's X25519 public key
        id_pub_a.clone(),
        id_priv_a,
        id_pub_b.clone(),
        true,  // Alice is initiator
    );

    // Bob's send = Alice's receive
    let bob = Session::new_with_ecdh(
        1,
        rk_bob,
        ko_bob,
        ckr_bob,  // Bob's send = Alice's receive
        cks_bob,  // Bob's receive = Alice's send
        kem_pub_b,
        kem_priv_b,
        ecdh_pub_b,
        ecdh_priv_b,
        ecdh_pub_a, // Peer's X25519 public key
        id_pub_b,
        id_priv_b,
        id_pub_a,
        false,  // Bob is responder
    );

    // Ko Enhancement: Add independent entropy from both parties
    // This provides defense-in-depth against KEM compromise
    
    // Phase 1: Exchange commitments
    let alice_commit = alice.ko_start_enhancement(&ss_alice).unwrap();
    let bob_commit = bob.ko_start_enhancement(&ss_bob).unwrap();
    
    // Phase 2: Exchange reveals
    let alice_reveal = alice.ko_process_commit(&bob_commit).unwrap();
    let bob_reveal = bob.ko_process_commit(&alice_commit).unwrap();
    
    // Phase 3: Finalize enhanced Ko
    alice.ko_finalize(&bob_reveal).unwrap();
    bob.ko_finalize(&alice_reveal).unwrap();

    // Send encrypted message
    let msg = alice.send(b"Quantum-safe hello").unwrap();
    let pt = bob.receive(&msg).unwrap();
    println!("{}", String::from_utf8_lossy(&pt)); // "Quantum-safe hello"
}
```

### Running the Rust Demo

```bash
make rust-run
# or directly:
cd clients/rust && cargo run --bin dice52-demo
```

### Building Rust

```bash
make rust-build
# or directly:
cd clients/rust && cargo build --release
```

### Running Tests

```bash
make rust-test
# or directly:
cd clients/rust && cargo test
```

---

## Project Structure

```
dice52/
├── clients/
│   ├── golang/                  # Go implementation
│   │   ├── cmd/dice52/          # Go executable demo
│   │   │   └── main.go
│   │   ├── pkg/dice52/          # Go library code
│   │   │   ├── types.go         # Constants & types
│   │   │   ├── kdf.go           # Key derivation (HKDF)
│   │   │   ├── handshake.go     # Handshake protocol
│   │   │   ├── crypto.go        # ChaCha20-Poly1305 encryption
│   │   │   ├── session.go       # Session management
│   │   │   └── ko_enhancement_test.go  # Ko enhancement tests
│   │   ├── go.mod               # Go module
│   │   └── go.sum
│   ├── rust/                    # Rust implementation
│   │   ├── src/                 # Rust library code
│   │   │   ├── lib.rs           # Library entry point
│   │   │   ├── types.rs         # Constants & types
│   │   │   ├── kdf.rs           # Key derivation (HKDF)
│   │   │   ├── handshake.rs     # Handshake protocol
│   │   │   ├── crypto.rs        # ChaCha20-Poly1305 encryption
│   │   │   ├── session.rs       # Session management
│   │   │   ├── error.rs         # Error types
│   │   │   └── bin/
│   │   │       └── dice52.rs    # Rust demo executable
│   │   ├── benches/
│   │   │   └── benchmarks.rs    # Rust benchmarks
│   │   ├── Cargo.toml           # Rust crate manifest
│   │   └── Cargo.lock
│   ├── python3/                 # Python 3 implementation
│   │   ├── dice52/              # Python package
│   │   │   ├── __init__.py
│   │   │   ├── types.py         # Constants & types
│   │   │   ├── kdf.py           # Key derivation (HKDF)
│   │   │   ├── handshake.py     # Handshake protocol
│   │   │   ├── crypto.py        # ChaCha20-Poly1305 encryption
│   │   │   ├── session.py       # Session management
│   │   │   └── demo.py          # Demo executable
│   │   ├── tests/               # Unit tests
│   │   ├── pyproject.toml       # Python package config
│   │   ├── requirements.txt     # Dependencies
│   │   └── Makefile
│   └── java/                    # Java implementation
│       ├── src/main/java/io/dice52/
│       │   ├── Types.java       # Constants & types
│       │   ├── Kdf.java         # Key derivation (HKDF)
│       │   ├── Handshake.java   # Handshake protocol
│       │   ├── Crypto.java      # ChaCha20-Poly1305 encryption
│       │   ├── Session.java     # Session management
│       │   └── Demo.java        # Demo executable
│       ├── src/test/java/       # Unit tests
│       ├── pom.xml              # Maven config
│       └── Makefile
├── Makefile                     # Build commands for Go/Rust
├── rfc-dice52-pq-protocol.md    # Protocol specification
└── README.md
```

## Makefile Targets

| Target | Description |
|--------|-------------|
| `make build` | Build Go binary |
| `make test` | Run Go tests |
| `make run` | Run Go demo |
| `make rust-build` | Build Rust release |
| `make rust-test` | Run Rust tests |
| `make rust-run` | Run Rust demo |
| `make rust-bench` | Run Rust benchmarks |
| `make all-build` | Build both Go and Rust |
| `make all-test` | Test both Go and Rust |
| `make all-clean` | Clean both Go and Rust |
