package dice52

import (
	"crypto/sha256"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/hkdf"
)

// hkdfExpand derives a key using HKDF-SHA256 (Section 3.2)
func hkdfExpand(secret, info []byte) []byte {
	h := hkdf.New(sha256.New, secret, nil, info)
	out := make([]byte, KeyLen)
	io.ReadFull(h, out)
	return out
}

// DeriveInitialKeys derives RK and Ko from shared secret (Section 8)
func DeriveInitialKeys(ss []byte) (rk, ko []byte) {
	rk = hkdfExpand(ss, []byte(RKInfo))
	ko = hkdfExpand(rk, []byte(KoInfo))
	return
}

// InitChainKeys initializes CKs and CKr from RK and Ko (Section 9)
func InitChainKeys(rk, ko []byte) (cks, ckr []byte) {
	// CKs = HKDF(RK, "Dice52-CKs" || Ko)
	cks = hkdfExpand(rk, append([]byte(CKsInfo), ko...))
	// CKr = HKDF(RK, "Dice52-CKr" || Ko)
	ckr = hkdfExpand(rk, append([]byte(CKrInfo), ko...))
	return
}

// RatchetRK performs a PQ ratchet step (Section 13.2)
func RatchetRK(oldRK, ss, ko []byte) (newRK []byte) {
	// RK = HKDF(RK || SSᵣ || Ko, "Dice52-RK-Ratchet")
	combined := append(oldRK, ss...)
	combined = append(combined, ko...)
	return hkdfExpand(combined, []byte(RKRatchetInfo))
}

// CKtoMK derives the next chain key and message key direction-bound MK derivation (Section 10)
// CK_next || MK = HKDF(CK, "Dice52-MK" || Ko || n)
func CKtoMK(ck, ko []byte, n uint64, dir byte, salt []byte) (nextCK, mk []byte) {
	buf := make([]byte, 9)
	buf[0] = dir
	binary.BigEndian.PutUint64(buf[1:], n)

	info := append([]byte(MKInfo), ko...)
	info = append(info, buf...)

	h := hkdf.New(sha256.New, ck, salt, info)
	out := make([]byte, 64)
	io.ReadFull(h, out)

	return out[:32], out[32:]
}

// ============================================================================
// Ko Enhancement Functions (Section 7.1)
// ============================================================================

// DeriveKoCommitKey derives the temporary key for Ko enhancement commit/reveal encryption
func DeriveKoCommitKey(ss []byte) []byte {
	return hkdfExpand(ss, []byte(KoCommitKeyInfo))
}

// CommitEntropy creates a commitment to entropy (Section 7.1.2)
func CommitEntropy(sessionID uint32, entropy []byte) []byte {
	h := sha256.New()
	h.Write([]byte(KoCommitPrefix))
	sidBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(sidBytes, sessionID)
	h.Write(sidBytes)
	h.Write(entropy)
	return h.Sum(nil)
}

// VerifyCommit verifies an entropy commitment (Section 7.1.3)
func VerifyCommit(sessionID uint32, entropy, commit []byte) bool {
	expected := CommitEntropy(sessionID, entropy)
	return constantTimeEqual(expected, commit)
}

// constantTimeEqual performs constant-time comparison
func constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := range a {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

// DeriveEnhancedKo derives enhanced Ko with contributed entropy from both parties (Section 7.1.4)
func DeriveEnhancedKo(koBase, rInitiator, rResponder []byte) []byte {
	combined := append(koBase, rInitiator...)
	combined = append(combined, rResponder...)
	return hkdfExpand(combined, []byte(KoEnhancedInfo))
}
