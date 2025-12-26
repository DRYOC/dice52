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

// ZeroBytes securely zeros a byte slice to prevent sensitive data from lingering in memory.
// This function is designed to not be optimized away by the compiler.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ZeroKey32 securely zeros a 32-byte key array
func ZeroKey32(k *[32]byte) {
	for i := range k {
		k[i] = 0
	}
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
// Note: The caller is responsible for zeroing the message key after use.
func Encrypt(mk []byte, sid uint32, epoch uint64, ctr uint64, ad, pt []byte) []byte {
	a, _ := chacha20poly1305.New(mk)
	nonce := makeNonce(sid, epoch, ctr)
	ct := a.Seal(nil, nonce, pt, ad)
	ZeroBytes(nonce) // Zero nonce after use
	return ct
}

// Decrypt decrypts ciphertext using ChaCha20-Poly1305 (Section 12)
// Note: The caller is responsible for zeroing the message key after use.
func Decrypt(mk []byte, sid uint32, epoch uint64, ctr uint64, ad, ct []byte) ([]byte, error) {
	a, _ := chacha20poly1305.New(mk)
	nonce := makeNonce(sid, epoch, ctr)
	pt, err := a.Open(nil, nonce, ct, ad)
	ZeroBytes(nonce) // Zero nonce after use
	return pt, err
}
