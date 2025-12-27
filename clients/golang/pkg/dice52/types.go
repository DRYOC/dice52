package dice52

import (
	"errors"
	"sync"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

const (
	Version = 1

	// Protocol-specified info strings (Section 8, 9, 10)
	RKInfo  = "Dice52-RK"
	KoInfo  = "Dice52-Ko"
	CKsInfo = "Dice52-CKs"
	CKrInfo = "Dice52-CKr"
	MKInfo  = "Dice52-MK"

	// Ratchet info (Section 13)
	RKRatchetInfo = "Dice52-RK-Ratchet"

	// Hybrid KEM info string (Section 3.4)
	HybridSSInfo = "Dice52-Hybrid-SS"

	// Ko enhancement info strings (Section 7.1)
	KoCommitPrefix  = "Dice52-Ko-Commit"
	KoCommitKeyInfo = "Dice52-Ko-CommitKey"
	KoEnhancedInfo  = "Dice52-Ko-Enhanced"

	// Signature context (Section 4)
	SigContext = "Dice52-PQ-Signature"

	KeyLen = 32

	// X25519 key sizes
	X25519PublicKeySize  = 32
	X25519PrivateKeySize = 32

	// Section 14: Default maximum messages per epoch
	DefaultMaxMessagesPerEpoch = 33
)

// ParanoidConfig configures paranoid mode settings (Section 7.2)
type ParanoidConfig struct {
	// Enabled activates paranoid mode
	Enabled bool
	// KoReenhanceInterval specifies how often to re-run Ko commit-reveal (in epochs)
	// Value of 0 means never re-enhance after initial enhancement
	KoReenhanceInterval uint64
	// MaxMessagesPerEpoch overrides the default 33 messages per epoch
	// Must be >= 1 and <= 33
	MaxMessagesPerEpoch uint64
}

// DefaultParanoidConfig returns a sensible default paranoid configuration
func DefaultParanoidConfig() ParanoidConfig {
	return ParanoidConfig{
		Enabled:             true,
		KoReenhanceInterval: 10, // Re-enhance Ko every 10 epochs
		MaxMessagesPerEpoch: 16, // Reduced from 33 to 16
	}
}

// Validate checks if the paranoid config is valid
func (c ParanoidConfig) Validate() error {
	if c.MaxMessagesPerEpoch < 1 {
		return errors.New("MaxMessagesPerEpoch must be >= 1")
	}
	if c.MaxMessagesPerEpoch > 33 {
		return errors.New("MaxMessagesPerEpoch must be <= 33")
	}
	return nil
}

// Session holds the state for a Dice52 PQ ratchet session
type Session struct {
	mu sync.Mutex

	// Root & chains
	RK  []byte
	CKs []byte
	CKr []byte
	Ko  []byte

	Ns    uint64
	Nr    uint64
	Epoch uint64 // Section 5: Rekey epoch counter

	// PQ ratchet keys (Kyber)
	KEMPriv *kyber768.PrivateKey
	KEMPub  *kyber768.PublicKey

	// X25519 keys for hybrid KEM (Section 3.1)
	ECDHPriv []byte // X25519 private key (32 bytes)
	ECDHPub  []byte // X25519 public key (32 bytes)

	// Peer's X25519 public key
	PeerECDHPub []byte

	// 🔐 Identity keys (Dilithium)
	IDPriv *mode3.PrivateKey
	IDPub  *mode3.PublicKey
	PeerID *mode3.PublicKey

	SessionID uint32

	// Ko enhancement state (Section 7.1)
	koEnhancement *KoEnhancementState
	koEnhanced    bool
	isInitiator   bool

	// Paranoid mode (Section 7.2)
	paranoidConfig      ParanoidConfig
	lastKoEnhancedEpoch uint64 // Epoch when Ko was last enhanced
	pendingKoReenhance  bool   // Flag indicating Ko re-enhancement is needed
	lastSharedSecret    []byte // Stored for Ko re-enhancement (only in paranoid mode)
}

// KoEnhancementState holds state during Ko enhancement protocol
type KoEnhancementState struct {
	TK           []byte // Temporary key for commit/reveal encryption
	LocalEntropy []byte // Our local entropy
	LocalCommit  []byte // Our commitment
	PeerCommit   []byte // Peer's commitment (set after receiving)
	PeerEntropy  []byte // Peer's entropy (set after reveal)
}

// Zero securely clears all sensitive data in the Ko enhancement state
func (s *KoEnhancementState) Zero() {
	if s == nil {
		return
	}
	for i := range s.TK {
		s.TK[i] = 0
	}
	for i := range s.LocalEntropy {
		s.LocalEntropy[i] = 0
	}
	for i := range s.LocalCommit {
		s.LocalCommit[i] = 0
	}
	for i := range s.PeerCommit {
		s.PeerCommit[i] = 0
	}
	for i := range s.PeerEntropy {
		s.PeerEntropy[i] = 0
	}
}

// KoCommitMessage is used for Ko enhancement commit phase (Section 7.1.2)
type KoCommitMessage struct {
	CommitCT []byte // Encrypted SHA-256 commitment
}

// KoRevealMessage is used for Ko enhancement reveal phase (Section 7.1.3)
type KoRevealMessage struct {
	RevealCT []byte // Encrypted local entropy
}

// HandshakeMessage is used to send and receive the handshake messages (Section 6.2)
// Now includes X25519 public key for hybrid KEM
type HandshakeMessage struct {
	KyberCT []byte // Post-quantum ciphertext
	ECDHPub []byte // X25519 ephemeral public key (32 bytes)
	Sig     []byte // Signature over KyberCT || ECDHPub
}

// Message represents an encrypted message with header and body
type Message struct {
	Header string
	Body   string
}

// RatchetMessage is used for hybrid PQ ratchet key exchange (Section 12)
type RatchetMessage struct {
	PubKey  []byte // Kyber public key (for initiator)
	ECDHPub []byte // X25519 public key (32 bytes)
	Sig     []byte // Signature over PubKey || ECDHPub
	CT      []byte // Kyber ciphertext (for responder)
}

// Header includes all AD fields required by Section 11.1
type Header struct {
	Version   uint8  `json:"v"`
	Epoch     uint64 `json:"e"`
	MsgNum    uint64 `json:"n"`
	Direction string `json:"d"` // "send" or "receive"
}
