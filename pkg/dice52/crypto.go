package dice52

import (
	"crypto/rand"
	"encoding/binary"

	"golang.org/x/crypto/chacha20poly1305"
)

// RandBytes generates n random bytes
func RandBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// makeNonce creates a nonce including session ID, epoch and message number
func makeNonce(sid uint32, epoch uint64, ctr uint64) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint32(n[0:4], sid)
	binary.BigEndian.PutUint32(n[4:8], uint32(epoch))
	binary.BigEndian.PutUint32(n[8:12], uint32(ctr))
	return n
}

// Encrypt encrypts plaintext using ChaCha20-Poly1305 (Section 11.2)
func Encrypt(mk []byte, sid uint32, epoch uint64, ctr uint64, ad, pt []byte) []byte {
	a, _ := chacha20poly1305.New(mk)
	nonce := makeNonce(sid, epoch, ctr)
	return a.Seal(nil, nonce, pt, ad)
}

// Decrypt decrypts ciphertext using ChaCha20-Poly1305 (Section 12)
func Decrypt(mk []byte, sid uint32, epoch uint64, ctr uint64, ad, ct []byte) ([]byte, error) {
	a, _ := chacha20poly1305.New(mk)
	nonce := makeNonce(sid, epoch, ctr)
	return a.Open(nil, nonce, ct, ad)
}

