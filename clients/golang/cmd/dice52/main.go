package main

import (
	"crypto/rand"
	"fmt"

	"github.com/dryoc/dice52/pkg/dice52"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

func main() {
	fmt.Println("=== Dice52 PQ Ratchet Demo (Go) ===")
	fmt.Println()

	// Generate Kyber KEM key pairs
	fmt.Println("Generating Kyber768 key pairs...")
	pubA, privA, _ := kyber768.Scheme().GenerateKeyPair()
	pubB, privB, _ := kyber768.Scheme().GenerateKeyPair()

	kemPubA := pubA.(*kyber768.PublicKey)
	kemPrivA := privA.(*kyber768.PrivateKey)
	kemPubB := pubB.(*kyber768.PublicKey)
	kemPrivB := privB.(*kyber768.PrivateKey)

	// Generate X25519 key pairs for hybrid KEM
	fmt.Println("Generating X25519 key pairs...")
	ecdhPubA, ecdhPrivA, err := dice52.GenerateX25519Keypair()
	if err != nil {
		fmt.Printf("X25519 key generation failed: %v\n", err)
		return
	}
	ecdhPubB, ecdhPrivB, err := dice52.GenerateX25519Keypair()
	if err != nil {
		fmt.Printf("X25519 key generation failed: %v\n", err)
		return
	}

	// Generate Dilithium key pairs
	fmt.Println("Generating Dilithium3 identity keys...")
	idPubA, idPrivA, _ := mode3.GenerateKey(rand.Reader)
	idPubB, idPrivB, _ := mode3.GenerateKey(rand.Reader)

	// Section 6.2: Alice performs hybrid encapsulation to Bob's public keys (Kyber + X25519)
	fmt.Println()
	fmt.Println("Alice performing hybrid encapsulation to Bob's public keys...")
	result, err := dice52.InitiatorHybridEncapsulate(kemPubB, ecdhPubB)
	if err != nil {
		fmt.Printf("Hybrid encapsulation failed: %v\n", err)
		return
	}

	// Bob performs hybrid decapsulation
	fmt.Println("Bob performing hybrid decapsulation...")
	ssBob, err := dice52.ResponderHybridDecapsulate(kemPrivB, ecdhPrivB, result.KyberCT, result.ECDHPub)
	if err != nil {
		fmt.Printf("Hybrid decapsulation failed: %v\n", err)
		return
	}

	// Verify shared secrets match
	ssAlice := result.SSHybrid
	if string(ssAlice) == string(ssBob) {
		fmt.Println("✓ Hybrid shared secrets match!")
	} else {
		fmt.Println("✗ Shared secrets don't match!")
		return
	}

	// Section 8: Derive RK and Ko
	fmt.Println()
	fmt.Println("Deriving initial keys...")
	rkAlice, koAlice := dice52.DeriveInitialKeys(ssAlice)
	rkBob, koBob := dice52.DeriveInitialKeys(ssBob)

	// Section 9: Initialize chain keys
	cksAlice, ckrAlice := dice52.InitChainKeys(rkAlice, koAlice)
	cksBob, ckrBob := dice52.InitChainKeys(rkBob, koBob)

	alice := &dice52.Session{
		SessionID:   1,
		RK:          rkAlice,
		Ko:          koAlice,
		CKs:         cksAlice,
		CKr:         ckrAlice,
		KEMPub:      kemPubA,
		KEMPriv:     kemPrivA,
		ECDHPub:     ecdhPubA,
		ECDHPriv:    ecdhPrivA,
		PeerECDHPub: ecdhPubB,
		IDPriv:      idPrivA,
		IDPub:       idPubA,
		PeerID:      idPubB,
		Epoch:       0,
	}

	bob := &dice52.Session{
		SessionID:   1,
		RK:          rkBob,
		Ko:          koBob,
		CKs:         ckrBob, // Bob's send = Alice's receive
		CKr:         cksBob, // Bob's receive = Alice's send
		KEMPub:      kemPubB,
		KEMPriv:     kemPrivB,
		ECDHPub:     ecdhPubB,
		ECDHPriv:    ecdhPrivB,
		PeerECDHPub: ecdhPubA,
		IDPriv:      idPrivB,
		IDPub:       idPubB,
		PeerID:      idPubA,
		Epoch:       0,
	}

	// Exchange messages
	fmt.Println()
	fmt.Println("--- Message Exchange ---")

	messages := []string{
		"Hello Bob! This is quantum-safe.",
		"Ready for the post-quantum era?",
		"Harvest now, decrypt never!",
	}

	for _, plaintext := range messages {
		fmt.Printf("\nAlice sends: \"%s\"\n", plaintext)
		msg, err := alice.Send([]byte(plaintext))
		if err != nil {
			fmt.Printf("Send failed: %v\n", err)
			return
		}

		pt, err := bob.Receive(msg)
		if err != nil {
			fmt.Printf("Receive failed: %v\n", err)
			return
		}
		fmt.Printf("Bob receives: \"%s\"\n", string(pt))
	}

	fmt.Println()
	fmt.Println("✓ All messages exchanged successfully!")

	// Demonstrate ratcheting with hybrid KEM
	fmt.Println()
	fmt.Println("--- Hybrid PQ Ratchet ---")
	fmt.Println("Alice initiating hybrid ratchet...")
	ratchetMsg, err := alice.InitiateRatchet()
	if err != nil {
		fmt.Printf("Ratchet initiation failed: %v\n", err)
		return
	}
	fmt.Printf("  Kyber public key size: %d bytes\n", len(ratchetMsg.PubKey))
	fmt.Printf("  X25519 public key size: %d bytes\n", len(ratchetMsg.ECDHPub))
	fmt.Printf("  Signature size: %d bytes\n", len(ratchetMsg.Sig))

	fmt.Println("Bob responding to hybrid ratchet...")
	response, err := bob.RespondRatchet(ratchetMsg)
	if err != nil {
		fmt.Printf("Ratchet response failed: %v\n", err)
		return
	}
	fmt.Printf("  Kyber ciphertext size: %d bytes\n", len(response.CT))

	fmt.Println("Alice finalizing hybrid ratchet...")
	err = alice.FinalizeRatchet(response)
	if err != nil {
		fmt.Printf("Ratchet finalization failed: %v\n", err)
		return
	}
	fmt.Printf("✓ Hybrid ratchet complete! New epoch: %d\n", alice.Epoch)

	// Send message after ratchet
	fmt.Println()
	fmt.Println("--- Post-Ratchet Message ---")
	postRatchetMsg := "This message uses new hybrid keys!"
	fmt.Printf("Alice sends: \"%s\"\n", postRatchetMsg)
	msg, err := alice.Send([]byte(postRatchetMsg))
	if err != nil {
		fmt.Printf("Send failed: %v\n", err)
		return
	}
	pt, err := bob.Receive(msg)
	if err != nil {
		fmt.Printf("Receive failed: %v\n", err)
		return
	}
	fmt.Printf("Bob receives: \"%s\"\n", string(pt))

	fmt.Println()
	fmt.Println("=== Demo Complete ===")
}
