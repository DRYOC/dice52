package main

import (
	"crypto/rand"
	"fmt"

	"github.com/dryoc/dice52/pkg/dice52"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

func main() {
	// Generate KEM key pairs
	pubA, privA, _ := kyber768.Scheme().GenerateKeyPair()
	pubB, privB, _ := kyber768.Scheme().GenerateKeyPair()

	kemPubA := pubA.(*kyber768.PublicKey)
	kemPrivA := privA.(*kyber768.PrivateKey)
	kemPubB := pubB.(*kyber768.PublicKey)
	kemPrivB := privB.(*kyber768.PrivateKey)

	// Generate Dilithium key pairs
	idPubA, idPrivA, _ := mode3.GenerateKey(rand.Reader)
	idPubB, idPrivB, _ := mode3.GenerateKey(rand.Reader)

	// Section 7: Alice encapsulates to Bob's public key
	ss, ct, err := dice52.InitiatorEncapsulate(kemPubB)
	if err != nil {
		fmt.Printf("Encapsulation failed: %v\n", err)
		return
	}

	// Bob decapsulates
	ssBob, err := dice52.ResponderDecapsulate(kemPrivB, ct)
	if err != nil {
		fmt.Printf("Decapsulation failed: %v\n", err)
		return
	}

	// Section 8: Derive RK and Ko
	rkAlice, koAlice := dice52.DeriveInitialKeys(ss)
	rkBob, koBob := dice52.DeriveInitialKeys(ssBob)

	// Section 9: Initialize chain keys
	cksAlice, ckrAlice := dice52.InitChainKeys(rkAlice, koAlice)
	cksBob, ckrBob := dice52.InitChainKeys(rkBob, koBob)

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
		Epoch:     0,
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
		Epoch:     0,
	}

	// Send a message from Alice to Bob
	msg, err := alice.Send([]byte("Quantum-safe hello"))
	if err != nil {
		fmt.Printf("Send failed: %v\n", err)
		return
	}

	pt, err := bob.Receive(msg)
	if err != nil {
		fmt.Printf("Receive failed: %v\n", err)
		return
	}

	fmt.Println(string(pt))

	// Send a reply from Bob to Alice
	msg2, err := bob.Send([]byte("Hello back from Bob!"))
	if err != nil {
		fmt.Printf("Send failed: %v\n", err)
		return
	}

	pt2, err := alice.Receive(msg2)
	if err != nil {
		fmt.Printf("Receive failed: %v\n", err)
		return
	}

	fmt.Println(string(pt2))
}
