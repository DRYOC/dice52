package dice52

import (
	"crypto/rand"
	"errors"

	"github.com/cloudflare/circl/dh/x25519"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

// GenerateX25519Keypair generates a new X25519 key pair
func GenerateX25519Keypair() (pub, priv []byte, err error) {
	var privKey x25519.Key
	var pubKey x25519.Key

	if _, err := rand.Read(privKey[:]); err != nil {
		return nil, nil, err
	}

	x25519.KeyGen(&pubKey, &privKey)

	return pubKey[:], privKey[:], nil
}

// X25519SharedSecret computes the X25519 shared secret
func X25519SharedSecret(ourPriv, peerPub []byte) ([]byte, error) {
	if len(ourPriv) != 32 || len(peerPub) != 32 {
		return nil, errors.New("invalid X25519 key length")
	}

	var priv, pub, ss x25519.Key
	copy(priv[:], ourPriv)
	copy(pub[:], peerPub)

	if !x25519.Shared(&ss, &priv, &pub) {
		return nil, errors.New("X25519 shared secret computation failed")
	}

	return ss[:], nil
}

// InitiatorHandshake is used to send the handshake message to the peer using hybrid KEM (Section 6.2)
// Returns the handshake message, hybrid shared secret, and our X25519 private key for session storage
func InitiatorHandshake(peerKEM *kyber768.PublicKey, peerECDH []byte, idPriv *mode3.PrivateKey) (*HandshakeMessage, []byte, []byte, error) {
	// Step 1: Generate ephemeral X25519 key pair
	ecdhPub, ecdhPriv, err := GenerateX25519Keypair()
	if err != nil {
		return nil, nil, nil, err
	}

	// Step 2: Kyber encapsulation
	ct, ssPQ, err := kyber768.Scheme().Encapsulate(peerKEM)
	if err != nil {
		return nil, nil, nil, err
	}

	// Step 3: X25519 key agreement
	ssECDH, err := X25519SharedSecret(ecdhPriv, peerECDH)
	if err != nil {
		return nil, nil, nil, err
	}

	// Step 4: Derive hybrid shared secret
	ssHybrid := DeriveHybridSharedSecret(ssPQ, ssECDH)

	// Step 5: Sign all handshake inputs (SigContext || KyberCT || ECDHPub)
	toSign := append([]byte(SigContext), ct...)
	toSign = append(toSign, ecdhPub...)
	sig := make([]byte, mode3.SignatureSize)
	mode3.SignTo(idPriv, toSign, sig)

	return &HandshakeMessage{KyberCT: ct, ECDHPub: ecdhPub, Sig: sig}, ssHybrid, ecdhPriv, nil
}

// ResponderHandshake is used to receive the handshake message from the peer using hybrid KEM (Section 6.3)
// Returns the hybrid shared secret
func ResponderHandshake(msg *HandshakeMessage, kemPriv *kyber768.PrivateKey, ecdhPriv []byte, peerID *mode3.PublicKey) ([]byte, error) {
	// Step 1: Verify signature over SigContext || KyberCT || ECDHPub
	toVerify := append([]byte(SigContext), msg.KyberCT...)
	toVerify = append(toVerify, msg.ECDHPub...)
	if !mode3.Verify(peerID, toVerify, msg.Sig) {
		return nil, errors.New("handshake signature invalid")
	}

	// Step 2: Decapsulate Kyber ciphertext
	ssPQ, err := kyber768.Scheme().Decapsulate(kemPriv, msg.KyberCT)
	if err != nil {
		return nil, err
	}

	// Step 3: X25519 key agreement
	ssECDH, err := X25519SharedSecret(ecdhPriv, msg.ECDHPub)
	if err != nil {
		return nil, err
	}

	// Step 4: Derive hybrid shared secret
	ssHybrid := DeriveHybridSharedSecret(ssPQ, ssECDH)

	return ssHybrid, nil
}

// HybridEncapsulateResult holds the result of hybrid encapsulation
type HybridEncapsulateResult struct {
	SSHybrid []byte // Combined hybrid shared secret
	KyberCT  []byte // Kyber ciphertext
	ECDHPub  []byte // Our X25519 public key
	ECDHPriv []byte // Our X25519 private key (for session storage)
}

// InitiatorHybridEncapsulate: Alice encapsulates to Bob's public keys using hybrid KEM
// Returns the hybrid shared secret, Kyber CT, and X25519 public key
func InitiatorHybridEncapsulate(peerKEM *kyber768.PublicKey, peerECDH []byte) (*HybridEncapsulateResult, error) {
	// Generate ephemeral X25519 key pair
	ecdhPub, ecdhPriv, err := GenerateX25519Keypair()
	if err != nil {
		return nil, err
	}

	// Kyber encapsulation
	ct, ssPQ, err := kyber768.Scheme().Encapsulate(peerKEM)
	if err != nil {
		return nil, err
	}

	// X25519 key agreement
	ssECDH, err := X25519SharedSecret(ecdhPriv, peerECDH)
	if err != nil {
		return nil, err
	}

	// Derive hybrid shared secret
	ssHybrid := DeriveHybridSharedSecret(ssPQ, ssECDH)

	return &HybridEncapsulateResult{
		SSHybrid: ssHybrid,
		KyberCT:  ct,
		ECDHPub:  ecdhPub,
		ECDHPriv: ecdhPriv,
	}, nil
}

// ResponderHybridDecapsulate: Bob decapsulates using his private keys (hybrid KEM)
// Returns the hybrid shared secret
func ResponderHybridDecapsulate(kemPriv *kyber768.PrivateKey, ecdhPriv []byte, kyberCT, peerECDHPub []byte) ([]byte, error) {
	// Decapsulate Kyber ciphertext
	ssPQ, err := kyber768.Scheme().Decapsulate(kemPriv, kyberCT)
	if err != nil {
		return nil, err
	}

	// X25519 key agreement
	ssECDH, err := X25519SharedSecret(ecdhPriv, peerECDHPub)
	if err != nil {
		return nil, err
	}

	// Derive hybrid shared secret
	ssHybrid := DeriveHybridSharedSecret(ssPQ, ssECDH)

	return ssHybrid, nil
}

// Legacy functions for backwards compatibility (Kyber-only)

// InitiatorEncapsulate: Alice encapsulates to Bob's public key (Kyber-only, legacy)
// Returns the shared secret and ciphertext to send to Bob
func InitiatorEncapsulate(peerPub *kyber768.PublicKey) (ss, ct []byte, err error) {
	ct, ss, err = kyber768.Scheme().Encapsulate(peerPub)
	return ss, ct, err
}

// ResponderDecapsulate: Bob decapsulates using his private key (Kyber-only, legacy)
func ResponderDecapsulate(ourPriv *kyber768.PrivateKey, ct []byte) ([]byte, error) {
	return kyber768.Scheme().Decapsulate(ourPriv, ct)
}
