package dice52

import (
	"errors"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

// InitiatorHandshake is used to send the handshake message to the peer using Dilithium mode3 signature
func InitiatorHandshake(peerKEM *kyber768.PublicKey, idPriv *mode3.PrivateKey) (*HandshakeMessage, []byte, error) {
	ct, ss, err := kyber768.Scheme().Encapsulate(peerKEM)
	if err != nil {
		return nil, nil, err
	}

	msg := append([]byte(SigContext), ct...)
	sig := make([]byte, mode3.SignatureSize)
	mode3.SignTo(idPriv, msg, sig)

	return &HandshakeMessage{KyberCT: ct, Sig: sig}, ss, nil
}

// ResponderHandshake is used to receive the handshake message from the peer and verify the signature using Dilithium mode3 signature
func ResponderHandshake(msg *HandshakeMessage, kemPriv *kyber768.PrivateKey, peerID *mode3.PublicKey) ([]byte, error) {
	toVerify := append([]byte(SigContext), msg.KyberCT...)
	if !mode3.Verify(peerID, toVerify, msg.Sig) {
		return nil, errors.New("handshake signature invalid")
	}

	return kyber768.Scheme().Decapsulate(kemPriv, msg.KyberCT)
}

// InitiatorEncapsulate: Alice encapsulates to Bob's public key (Section 7)
// Returns the shared secret and ciphertext to send to Bob
func InitiatorEncapsulate(peerPub *kyber768.PublicKey) (ss, ct []byte, err error) {
	ct, ss, err = kyber768.Scheme().Encapsulate(peerPub)
	return ss, ct, err
}

// ResponderDecapsulate: Bob decapsulates using his private key (Section 7)
func ResponderDecapsulate(ourPriv *kyber768.PrivateKey, ct []byte) ([]byte, error) {
	return kyber768.Scheme().Decapsulate(ourPriv, ct)
}

