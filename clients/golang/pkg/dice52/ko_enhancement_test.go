package dice52

import (
	"testing"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

func createTestSessions(t *testing.T) (*Session, *Session, []byte) {
	t.Helper()

	// Generate KEM key pairs
	kemPubA, kemPrivA, err := kyber768.Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate KEM keypair A: %v", err)
	}
	kemPubB, kemPrivB, err := kyber768.Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate KEM keypair B: %v", err)
	}

	// Generate identity key pairs
	idPubA, idPrivA, err := mode3.Scheme().GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate identity keypair A: %v", err)
	}
	idPubB, idPrivB, err := mode3.Scheme().GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate identity keypair B: %v", err)
	}

	// Alice encapsulates to Bob's public key
	ct, ss, err := kyber768.Scheme().Encapsulate(kemPubB)
	if err != nil {
		t.Fatalf("encapsulation failed: %v", err)
	}

	// Bob decapsulates
	ssBob, err := kyber768.Scheme().Decapsulate(kemPrivB.(*kyber768.PrivateKey), ct)
	if err != nil {
		t.Fatalf("decapsulation failed: %v", err)
	}

	// Derive initial keys
	rkAlice, koAlice := DeriveInitialKeys(ss)
	rkBob, koBob := DeriveInitialKeys(ssBob)

	// Initialize chain keys
	cksAlice, ckrAlice := InitChainKeys(rkAlice, koAlice)
	cksBob, ckrBob := InitChainKeys(rkBob, koBob)

	alice := &Session{
		RK:          rkAlice,
		Ko:          koAlice,
		CKs:         cksAlice,
		CKr:         ckrAlice,
		KEMPub:      kemPubA.(*kyber768.PublicKey),
		KEMPriv:     kemPrivA.(*kyber768.PrivateKey),
		IDPub:       idPubA.(*mode3.PublicKey),
		IDPriv:      idPrivA.(*mode3.PrivateKey),
		PeerID:      idPubB.(*mode3.PublicKey),
		SessionID:   1,
		isInitiator: true,
	}

	// Bob's send = Alice's receive, Bob's receive = Alice's send
	bob := &Session{
		RK:          rkBob,
		Ko:          koBob,
		CKs:         ckrBob, // Swapped
		CKr:         cksBob, // Swapped
		KEMPub:      kemPubB.(*kyber768.PublicKey),
		KEMPriv:     kemPrivB.(*kyber768.PrivateKey),
		IDPub:       idPubB.(*mode3.PublicKey),
		IDPriv:      idPrivB.(*mode3.PrivateKey),
		PeerID:      idPubA.(*mode3.PublicKey),
		SessionID:   1,
		isInitiator: false,
	}

	return alice, bob, ss
}

func TestKoEnhancement(t *testing.T) {
	alice, bob, ss := createTestSessions(t)

	// Both sessions should start without Ko enhancement
	if alice.IsKoEnhanced() {
		t.Error("alice should not start with Ko enhanced")
	}
	if bob.IsKoEnhanced() {
		t.Error("bob should not start with Ko enhanced")
	}

	// Step 1: Both parties start enhancement and exchange commits
	aliceCommit, err := alice.KoStartEnhancement(ss)
	if err != nil {
		t.Fatalf("alice ko_start_enhancement failed: %v", err)
	}
	bobCommit, err := bob.KoStartEnhancement(ss)
	if err != nil {
		t.Fatalf("bob ko_start_enhancement failed: %v", err)
	}

	// Step 2: Process received commits and create reveals
	aliceReveal, err := alice.KoProcessCommit(bobCommit)
	if err != nil {
		t.Fatalf("alice ko_process_commit failed: %v", err)
	}
	bobReveal, err := bob.KoProcessCommit(aliceCommit)
	if err != nil {
		t.Fatalf("bob ko_process_commit failed: %v", err)
	}

	// Step 3: Finalize with received reveals
	if err := alice.KoFinalize(bobReveal); err != nil {
		t.Fatalf("alice ko_finalize failed: %v", err)
	}
	if err := bob.KoFinalize(aliceReveal); err != nil {
		t.Fatalf("bob ko_finalize failed: %v", err)
	}

	// Both sessions should now have enhanced Ko
	if !alice.IsKoEnhanced() {
		t.Error("alice should have Ko enhanced")
	}
	if !bob.IsKoEnhanced() {
		t.Error("bob should have Ko enhanced")
	}

	// Verify they can still communicate
	plaintext := []byte("Post-enhancement message!")
	msg, err := alice.Send(plaintext)
	if err != nil {
		t.Fatalf("send failed: %v", err)
	}
	decrypted, err := bob.Receive(msg)
	if err != nil {
		t.Fatalf("receive failed: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("decrypted message mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestKoEnhancementPreventsDoubleEnhancement(t *testing.T) {
	alice, bob, ss := createTestSessions(t)

	// Complete full enhancement
	aliceCommit, _ := alice.KoStartEnhancement(ss)
	bobCommit, _ := bob.KoStartEnhancement(ss)
	aliceReveal, _ := alice.KoProcessCommit(bobCommit)
	bobReveal, _ := bob.KoProcessCommit(aliceCommit)
	alice.KoFinalize(bobReveal)
	bob.KoFinalize(aliceReveal)

	// Starting again should fail (already enhanced)
	_, err := alice.KoStartEnhancement(ss)
	if err == nil {
		t.Error("expected error when starting enhancement after already enhanced")
	}
}

func TestKoEnhancementCommitMismatch(t *testing.T) {
	alice, bob, ss := createTestSessions(t)

	// Start enhancement
	_, _ = alice.KoStartEnhancement(ss)
	bobCommit, _ := bob.KoStartEnhancement(ss)

	// Alice processes Bob's commit
	_, _ = alice.KoProcessCommit(bobCommit)

	// Create a fake reveal with wrong ciphertext
	fakeReveal := &KoRevealMessage{
		RevealCT: make([]byte, 48),
	}

	// Finalization should fail
	err := alice.KoFinalize(fakeReveal)
	if err == nil {
		t.Error("expected error with fake reveal")
	}
}

func TestKdfKoEnhancementFunctions(t *testing.T) {
	t.Run("CommitVerify", func(t *testing.T) {
		sessionID := uint32(12345)
		entropy := make([]byte, 32)
		for i := range entropy {
			entropy[i] = 42
		}
		commit := CommitEntropy(sessionID, entropy)

		// Verification should succeed with correct entropy
		if !VerifyCommit(sessionID, entropy, commit) {
			t.Error("verification should succeed with correct entropy")
		}

		// Verification should fail with wrong entropy
		wrongEntropy := make([]byte, 32)
		for i := range wrongEntropy {
			wrongEntropy[i] = 99
		}
		if VerifyCommit(sessionID, wrongEntropy, commit) {
			t.Error("verification should fail with wrong entropy")
		}

		// Verification should fail with wrong session_id
		if VerifyCommit(99999, entropy, commit) {
			t.Error("verification should fail with wrong session_id")
		}
	})

	t.Run("DeriveEnhancedKo", func(t *testing.T) {
		koBase := make([]byte, 32)
		rInit := make([]byte, 32)
		rResp := make([]byte, 32)
		for i := range koBase {
			koBase[i] = 1
			rInit[i] = 2
			rResp[i] = 3
		}

		enhanced := DeriveEnhancedKo(koBase, rInit, rResp)
		if len(enhanced) != KeyLen {
			t.Errorf("enhanced Ko length = %d, want %d", len(enhanced), KeyLen)
		}

		// Should be deterministic
		enhanced2 := DeriveEnhancedKo(koBase, rInit, rResp)
		for i := range enhanced {
			if enhanced[i] != enhanced2[i] {
				t.Error("enhanced Ko should be deterministic")
				break
			}
		}

		// Different inputs should produce different outputs
		enhanced3 := DeriveEnhancedKo(koBase, rResp, rInit)
		same := true
		for i := range enhanced {
			if enhanced[i] != enhanced3[i] {
				same = false
				break
			}
		}
		if same {
			t.Error("different entropy order should produce different Ko")
		}
	})

	t.Run("DeriveKoCommitKey", func(t *testing.T) {
		ss := make([]byte, 32)
		for i := range ss {
			ss[i] = 5
		}
		tk := DeriveKoCommitKey(ss)
		if len(tk) != KeyLen {
			t.Errorf("TK length = %d, want %d", len(tk), KeyLen)
		}

		// Should be deterministic
		tk2 := DeriveKoCommitKey(ss)
		for i := range tk {
			if tk[i] != tk2[i] {
				t.Error("TK should be deterministic")
				break
			}
		}
	})
}
