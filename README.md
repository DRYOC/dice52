# Dice52

Dice52 is a quantum-safe ratchet protocol. It is a key agreement protocol that uses the Dilithium signature scheme to secure the key exchange.

Goal: A post-quantum, authenticated, forward-secret, per-message-key encryption protocol that preserves Dice52's Ko ordering concept.

**Available in both Go and Rust!**

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
X25519 | ML-KEM (Kyber)
Ed25519 | ML-DSA (Dilithium)
DH ratchet | KEM ratchet

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

## Go Library

### Installation

```bash
go get github.com/dryoc/dice52
```

### Usage

Import the package in your Go code:

```go
import "github.com/dryoc/dice52/pkg/dice52"
```

#### Example: Establishing a Session

```go
package main

import (
	"crypto/rand"
	"fmt"

	"github.com/dryoc/dice52/pkg/dice52"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

func main() {
	// Generate KEM key pairs for Alice and Bob
	pubA, privA, _ := kyber768.Scheme().GenerateKeyPair()
	pubB, privB, _ := kyber768.Scheme().GenerateKeyPair()

	kemPubA := pubA.(*kyber768.PublicKey)
	kemPrivA := privA.(*kyber768.PrivateKey)
	kemPubB := pubB.(*kyber768.PublicKey)
	kemPrivB := privB.(*kyber768.PrivateKey)

	// Generate Dilithium identity key pairs
	idPubA, idPrivA, _ := mode3.GenerateKey(rand.Reader)
	idPubB, idPrivB, _ := mode3.GenerateKey(rand.Reader)

	// Alice encapsulates to Bob's public key
	ss, ct, _ := dice52.InitiatorEncapsulate(kemPubB)

	// Bob decapsulates
	ssBob, _ := dice52.ResponderDecapsulate(kemPrivB, ct)

	// Derive initial keys
	rkAlice, koAlice := dice52.DeriveInitialKeys(ss)
	rkBob, koBob := dice52.DeriveInitialKeys(ssBob)

	// Initialize chain keys
	cksAlice, ckrAlice := dice52.InitChainKeys(rkAlice, koAlice)
	cksBob, ckrBob := dice52.InitChainKeys(rkBob, koBob)

	// Create sessions
	alice := &dice52.Session{
		SessionID: 1,
		RK:        rkAlice,
		Ko:        koAlice,
		CKs:       cksAlice,
		CKr:       ckrAlice,
		KEMPub:    kemPubA,
		KEMPriv:   kemPrivA,
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
		IDPriv:    idPrivB,
		IDPub:     idPubB,
		PeerID:    idPubA,
	}

	// Ko Enhancement: Add independent entropy from both parties
	// This provides defense-in-depth against KEM compromise
	alice.SetInitiator(true)
	bob.SetInitiator(false)
	
	// Phase 1: Exchange commitments
	aliceCommit, _ := alice.KoStartEnhancement(ss)
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
go run ./cmd/dice52
```

### Building Go

```bash
go build ./...
```

---

## Rust Crate

### Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
dice52 = { git = "https://github.com/dryoc/dice52" }
```

Or if published to crates.io:

```toml
[dependencies]
dice52 = "0.1"
```

### Usage

```rust
use dice52::{Session, derive_initial_keys, init_chain_keys, initiator_encapsulate, responder_decapsulate};
use pqcrypto_kyber::kyber768;
use pqcrypto_dilithium::dilithium3;

fn main() {
    // Generate KEM key pairs for Alice and Bob
    let (kem_pub_a, kem_priv_a) = kyber768::keypair();
    let (kem_pub_b, kem_priv_b) = kyber768::keypair();

    // Generate Dilithium identity key pairs
    let (id_pub_a, id_priv_a) = dilithium3::keypair();
    let (id_pub_b, id_priv_b) = dilithium3::keypair();

    // Alice encapsulates to Bob's public key
    let (ss_alice, ct) = initiator_encapsulate(&kem_pub_b);

    // Bob decapsulates
    let ss_bob = responder_decapsulate(&kem_priv_b, &ct).unwrap();

    // Derive initial keys
    let (rk_alice, ko_alice) = derive_initial_keys(&ss_alice);
    let (rk_bob, ko_bob) = derive_initial_keys(&ss_bob);

    // Initialize chain keys
    let (cks_alice, ckr_alice) = init_chain_keys(&rk_alice, &ko_alice);
    let (cks_bob, ckr_bob) = init_chain_keys(&rk_bob, &ko_bob);

    // Create sessions (with initiator/responder roles for Ko enhancement)
    let alice = Session::new_with_role(
        1,
        rk_alice,
        ko_alice,
        cks_alice,
        ckr_alice,
        kem_pub_a,
        kem_priv_a,
        id_pub_a.clone(),
        id_priv_a,
        id_pub_b.clone(),
        true,  // Alice is initiator
    );

    // Bob's send = Alice's receive
    let bob = Session::new_with_role(
        1,
        rk_bob,
        ko_bob,
        ckr_bob,  // Bob's send = Alice's receive
        cks_bob,  // Bob's receive = Alice's send
        kem_pub_b,
        kem_priv_b,
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
cargo run --bin dice52-demo
```

### Building Rust

```bash
cargo build --release
```

### Running Tests

```bash
cargo test
```

---

## Project Structure

```
dice52/
├── cmd/dice52/              # Go executable demo
│   └── main.go
├── pkg/dice52/              # Go library code
│   ├── types.go             # Constants & types
│   ├── kdf.go               # Key derivation (HKDF)
│   ├── handshake.go         # Handshake protocol
│   ├── crypto.go            # ChaCha20-Poly1305 encryption
│   ├── session.go           # Session management
│   └── ko_enhancement_test.go  # Ko enhancement tests
├── src/                     # Rust library code
│   ├── lib.rs               # Library entry point
│   ├── types.rs             # Constants & types
│   ├── kdf.rs               # Key derivation (HKDF)
│   ├── handshake.rs         # Handshake protocol
│   ├── crypto.rs            # ChaCha20-Poly1305 encryption
│   ├── session.rs           # Session management
│   ├── error.rs             # Error types
│   └── bin/
│       └── dice52.rs        # Rust demo executable
├── benches/
│   └── benchmarks.rs        # Rust benchmarks
├── Cargo.toml               # Rust crate manifest
├── go.mod                   # Go module
├── Makefile                 # Build commands for both
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
