package dice52

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"golang.org/x/crypto/chacha20poly1305"
)

// SetParanoidMode enables paranoid mode with the given configuration
func (s *Session) SetParanoidMode(config ParanoidConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := config.Validate(); err != nil {
		return fmt.Errorf("invalid paranoid config: %w", err)
	}

	s.paranoidConfig = config
	return nil
}

// GetParanoidConfig returns the current paranoid mode configuration
func (s *Session) GetParanoidConfig() ParanoidConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.paranoidConfig
}

// IsParanoidMode returns whether paranoid mode is enabled
func (s *Session) IsParanoidMode() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.paranoidConfig.Enabled
}

// NeedsKoReenhancement returns true if Ko re-enhancement is pending
func (s *Session) NeedsKoReenhancement() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pendingKoReenhance
}

// getMaxMessagesPerEpoch returns the configured max messages per epoch
func (s *Session) getMaxMessagesPerEpoch() uint64 {
	if s.paranoidConfig.Enabled && s.paranoidConfig.MaxMessagesPerEpoch > 0 {
		return s.paranoidConfig.MaxMessagesPerEpoch
	}
	return DefaultMaxMessagesPerEpoch
}

// Send encrypts and sends a message (Section 11)
func (s *Session) Send(pt []byte) (*Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Section 14: Enforce epoch limit (configurable in paranoid mode)
	maxMessages := s.getMaxMessagesPerEpoch()
	if s.Ns >= maxMessages {
		return nil, errors.New("epoch exhausted: rekey required")
	}

	nextCK, mk := CKtoMK(s.CKs, s.Ko, s.Ns, 0, s.RK)
	s.CKs = nextCK

	// Section 11.1: AD must include version, epoch, message number, direction
	h := Header{
		Version:   Version,
		Epoch:     s.Epoch,
		MsgNum:    s.Ns,
		Direction: "send",
	}
	ad, _ := json.Marshal(h)
	ct := Encrypt(mk, s.SessionID, s.Epoch, s.Ns, ad, pt)
	ZeroBytes(mk) // Zero message key after use
	s.Ns++

	return &Message{
		Header: base64.StdEncoding.EncodeToString(ad),
		Body:   base64.StdEncoding.EncodeToString(ct),
	}, nil
}

// Receive decrypts a received message (Section 12)
func (s *Session) Receive(m *Message) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ad, err := base64.StdEncoding.DecodeString(m.Header)
	if err != nil {
		return nil, fmt.Errorf("invalid header encoding: %w", err)
	}

	var h Header
	if err := json.Unmarshal(ad, &h); err != nil {
		return nil, fmt.Errorf("invalid header format: %w", err)
	}

	// Section 16: Message numbers must be monotonically increasing
	if h.MsgNum < s.Nr {
		return nil, errors.New("replay detected: message number too low")
	}

	ct, err := base64.StdEncoding.DecodeString(m.Body)
	if err != nil {
		return nil, fmt.Errorf("invalid body encoding: %w", err)
	}

	// Enforce epoch match on receive:
	if h.Epoch != s.Epoch {
		return nil, errors.New("epoch mismatch")
	}

	// Derive MK using message number from header (use dir=0 to match sender)
	nextCK, mk := CKtoMK(s.CKr, s.Ko, h.MsgNum, 0, s.RK)
	s.CKr = nextCK

	// Reconstruct AD with receive direction for decryption
	recvHeader := Header{
		Version:   h.Version,
		Epoch:     h.Epoch,
		MsgNum:    h.MsgNum,
		Direction: "send", // Match sender's AD
	}
	recvAD, _ := json.Marshal(recvHeader)

	pt, err := Decrypt(mk, s.SessionID, h.Epoch, h.MsgNum, recvAD, ct)
	ZeroBytes(mk) // Zero message key after use
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	s.Nr = h.MsgNum + 1
	return pt, nil
}

// applyRatchet performs a PQ ratchet step (Section 13)
func (s *Session) applyRatchet(ss []byte, asInitiator bool) {
	combined := append(append(s.RK, ss...), s.Ko...)
	s.RK = hkdfExpand(combined, []byte(RKRatchetInfo))
	s.Ko = hkdfExpand(s.RK, []byte(KoInfo))

	cks, ckr := InitChainKeys(s.RK, s.Ko)
	if asInitiator {
		// Ratchet initiator: CKs sends, CKr receives
		s.CKs = cks
		s.CKr = ckr
	} else {
		// Ratchet responder: swap keys (responder's send = initiator's receive)
		s.CKs = ckr
		s.CKr = cks
	}
	s.Ns = 0
	s.Nr = 0
	s.Epoch++

	// Paranoid mode: Check if Ko re-enhancement is needed (Section 7.2)
	if s.paranoidConfig.Enabled && s.paranoidConfig.KoReenhanceInterval > 0 {
		epochsSinceLastEnhance := s.Epoch - s.lastKoEnhancedEpoch
		if epochsSinceLastEnhance >= s.paranoidConfig.KoReenhanceInterval {
			s.pendingKoReenhance = true
			// Store shared secret for re-enhancement
			s.lastSharedSecret = make([]byte, len(ss))
			copy(s.lastSharedSecret, ss)
		}
	}
}

// InitiateRatchet starts a hybrid PQ ratchet with Dilithium signature (Section 12.2)
func (s *Session) InitiateRatchet() (*RatchetMessage, error) {
	// Generate new Kyber key pair
	pub, priv, err := kyber768.Scheme().GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	s.KEMPriv = priv.(*kyber768.PrivateKey)
	s.KEMPub = pub.(*kyber768.PublicKey)

	// Generate new X25519 key pair
	ecdhPub, ecdhPriv, err := GenerateX25519Keypair()
	if err != nil {
		return nil, err
	}

	s.ECDHPriv = ecdhPriv
	s.ECDHPub = ecdhPub

	// Sign both public keys: SigContext || KEMPub || ECDHPub
	pubBytes, _ := s.KEMPub.MarshalBinary()
	toSign := append([]byte(SigContext), pubBytes...)
	toSign = append(toSign, ecdhPub...)
	sig := make([]byte, mode3.SignatureSize)
	mode3.SignTo(s.IDPriv, toSign, sig)

	return &RatchetMessage{
		PubKey:  pubBytes,
		ECDHPub: ecdhPub,
		Sig:     sig,
	}, nil
}

// RespondRatchet is used to respond to initiator's hybrid ratchet message (Section 12.3)
func (s *Session) RespondRatchet(msg *RatchetMessage) (*RatchetMessage, error) {
	// Verify signature over SigContext || KEMPub || ECDHPub
	toVerify := append([]byte(SigContext), msg.PubKey...)
	toVerify = append(toVerify, msg.ECDHPub...)
	if !mode3.Verify(s.PeerID, toVerify, msg.Sig) {
		return nil, errors.New("ratchet signature invalid")
	}

	// Unmarshal peer's Kyber public key
	peerPub, err := kyber768.Scheme().UnmarshalBinaryPublicKey(msg.PubKey)
	if err != nil {
		return nil, err
	}

	// Store peer's X25519 public key
	s.PeerECDHPub = msg.ECDHPub

	// Generate ephemeral X25519 key pair for response
	ecdhPub, ecdhPriv, err := GenerateX25519Keypair()
	if err != nil {
		return nil, err
	}

	// Kyber encapsulation
	ct, ssPQ, err := kyber768.Scheme().Encapsulate(peerPub)
	if err != nil {
		return nil, err
	}

	// X25519 key agreement
	ssECDH, err := X25519SharedSecret(ecdhPriv, msg.ECDHPub)
	if err != nil {
		return nil, err
	}

	// Derive hybrid shared secret
	ssHybrid := DeriveHybridSharedSecret(ssPQ, ssECDH)

	s.applyRatchet(ssHybrid, false) // Responder
	return &RatchetMessage{CT: ct, ECDHPub: ecdhPub}, nil
}

// FinalizeRatchet completes the hybrid ratchet on the initiator side (Section 12.4)
func (s *Session) FinalizeRatchet(msg *RatchetMessage) error {
	// Decapsulate Kyber ciphertext
	ssPQ, err := kyber768.Scheme().Decapsulate(s.KEMPriv, msg.CT)
	if err != nil {
		return err
	}

	// X25519 key agreement with responder's ephemeral public key
	ssECDH, err := X25519SharedSecret(s.ECDHPriv, msg.ECDHPub)
	if err != nil {
		return err
	}

	// Derive hybrid shared secret
	ssHybrid := DeriveHybridSharedSecret(ssPQ, ssECDH)

	s.applyRatchet(ssHybrid, true) // Initiator
	return nil
}

// ============================================================================
// Ko Enhancement Protocol (Section 7.1)
// ============================================================================

// IsKoEnhanced returns whether Ko has been enhanced
func (s *Session) IsKoEnhanced() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.koEnhanced
}

// SetInitiator sets whether this session is the initiator
func (s *Session) SetInitiator(isInitiator bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.isInitiator = isInitiator
}

// KoStartEnhancement starts Ko enhancement: generate local entropy and create commit message
func (s *Session) KoStartEnhancement(ss []byte) (*KoCommitMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.koEnhanced {
		return nil, errors.New("ko already enhanced")
	}

	// Generate local entropy
	localEntropy := RandBytes(32)

	// Derive temporary key
	tk := DeriveKoCommitKey(ss)

	// Create commitment
	localCommit := CommitEntropy(s.SessionID, localEntropy)

	// Encrypt commitment with TK (nonce = 0 for commit)
	aead, err := chacha20poly1305.New(tk)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	nonce := make([]byte, 12) // All zeros for commit
	commitCT := aead.Seal(nil, nonce, localCommit, []byte("ko-commit"))

	// Store state
	s.koEnhancement = &KoEnhancementState{
		TK:           tk,
		LocalEntropy: localEntropy,
		LocalCommit:  localCommit,
	}

	return &KoCommitMessage{CommitCT: commitCT}, nil
}

// KoProcessCommit processes received commit and creates reveal message
func (s *Session) KoProcessCommit(peerCommitMsg *KoCommitMessage) (*KoRevealMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.koEnhancement == nil {
		return nil, errors.New("enhancement not started")
	}

	// Decrypt peer's commit
	aead, err := chacha20poly1305.New(s.koEnhancement.TK)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	nonce := make([]byte, 12) // All zeros for commit
	peerCommit, err := aead.Open(nil, nonce, peerCommitMsg.CommitCT, []byte("ko-commit"))
	if err != nil {
		return nil, fmt.Errorf("commit decryption failed: %w", err)
	}

	if len(peerCommit) != 32 {
		return nil, errors.New("invalid commit length")
	}

	s.koEnhancement.PeerCommit = peerCommit

	// Create reveal (encrypt our entropy with nonce = 1)
	revealNonce := make([]byte, 12)
	revealNonce[11] = 1
	revealCT := aead.Seal(nil, revealNonce, s.koEnhancement.LocalEntropy, []byte("ko-reveal"))

	return &KoRevealMessage{RevealCT: revealCT}, nil
}

// KoFinalize finalizes Ko enhancement with peer's reveal
func (s *Session) KoFinalize(peerRevealMsg *KoRevealMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.koEnhancement == nil {
		return errors.New("enhancement not started")
	}

	if s.koEnhancement.PeerCommit == nil {
		return errors.New("peer commit not received")
	}

	// Decrypt peer's reveal
	aead, err := chacha20poly1305.New(s.koEnhancement.TK)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	revealNonce := make([]byte, 12)
	revealNonce[11] = 1
	peerEntropy, err := aead.Open(nil, revealNonce, peerRevealMsg.RevealCT, []byte("ko-reveal"))
	if err != nil {
		return fmt.Errorf("reveal decryption failed: %w", err)
	}

	if len(peerEntropy) != 32 {
		return errors.New("invalid reveal length")
	}

	// Verify commit
	if !VerifyCommit(s.SessionID, peerEntropy, s.koEnhancement.PeerCommit) {
		return errors.New("ko commit verification failed: reveal does not match commitment")
	}

	// Determine initiator/responder entropy order
	var rInitiator, rResponder []byte
	if s.isInitiator {
		rInitiator = s.koEnhancement.LocalEntropy
		rResponder = peerEntropy
	} else {
		rInitiator = peerEntropy
		rResponder = s.koEnhancement.LocalEntropy
	}

	// Derive enhanced Ko
	s.Ko = DeriveEnhancedKo(s.Ko, rInitiator, rResponder)

	// Note: We do NOT reinitialize chain keys here.
	// Ko is used in message key derivation (CKtoMK), so updating Ko
	// is sufficient. Chain keys will continue to evolve naturally.

	// Zero and clear enhancement state
	s.koEnhancement.Zero()
	s.koEnhancement = nil
	s.koEnhanced = true

	// Track when Ko was last enhanced (for paranoid mode)
	s.lastKoEnhancedEpoch = s.Epoch
	s.pendingKoReenhance = false

	return nil
}

// ============================================================================
// Paranoid Mode Ko Re-enhancement (Section 7.2)
// ============================================================================

// KoStartReenhancement starts Ko re-enhancement during paranoid mode
// This should be called after a ratchet when NeedsKoReenhancement() returns true
func (s *Session) KoStartReenhancement() (*KoCommitMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.paranoidConfig.Enabled {
		return nil, errors.New("paranoid mode not enabled")
	}

	if !s.pendingKoReenhance {
		return nil, errors.New("ko re-enhancement not needed")
	}

	if s.lastSharedSecret == nil {
		return nil, errors.New("no shared secret available for re-enhancement")
	}

	// Generate local entropy
	localEntropy := RandBytes(32)

	// Derive temporary key from the ratchet shared secret
	tk := DeriveKoCommitKey(s.lastSharedSecret)

	// Create commitment
	localCommit := CommitEntropy(s.SessionID, localEntropy)

	// Encrypt commitment with TK (nonce = 0 for commit)
	aead, err := chacha20poly1305.New(tk)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	nonce := make([]byte, 12) // All zeros for commit
	commitCT := aead.Seal(nil, nonce, localCommit, []byte("ko-reenhance-commit"))

	// Store state
	s.koEnhancement = &KoEnhancementState{
		TK:           tk,
		LocalEntropy: localEntropy,
		LocalCommit:  localCommit,
	}

	return &KoCommitMessage{CommitCT: commitCT}, nil
}

// KoProcessReenhanceCommit processes received re-enhancement commit
func (s *Session) KoProcessReenhanceCommit(peerCommitMsg *KoCommitMessage) (*KoRevealMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.koEnhancement == nil {
		return nil, errors.New("re-enhancement not started")
	}

	// Decrypt peer's commit
	aead, err := chacha20poly1305.New(s.koEnhancement.TK)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	nonce := make([]byte, 12) // All zeros for commit
	peerCommit, err := aead.Open(nil, nonce, peerCommitMsg.CommitCT, []byte("ko-reenhance-commit"))
	if err != nil {
		return nil, fmt.Errorf("commit decryption failed: %w", err)
	}

	if len(peerCommit) != 32 {
		return nil, errors.New("invalid commit length")
	}

	s.koEnhancement.PeerCommit = peerCommit

	// Create reveal (encrypt our entropy with nonce = 1)
	revealNonce := make([]byte, 12)
	revealNonce[11] = 1
	revealCT := aead.Seal(nil, revealNonce, s.koEnhancement.LocalEntropy, []byte("ko-reenhance-reveal"))

	return &KoRevealMessage{RevealCT: revealCT}, nil
}

// KoFinalizeReenhancement finalizes Ko re-enhancement
func (s *Session) KoFinalizeReenhancement(peerRevealMsg *KoRevealMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.koEnhancement == nil {
		return errors.New("re-enhancement not started")
	}

	if s.koEnhancement.PeerCommit == nil {
		return errors.New("peer commit not received")
	}

	// Decrypt peer's reveal
	aead, err := chacha20poly1305.New(s.koEnhancement.TK)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	revealNonce := make([]byte, 12)
	revealNonce[11] = 1
	peerEntropy, err := aead.Open(nil, revealNonce, peerRevealMsg.RevealCT, []byte("ko-reenhance-reveal"))
	if err != nil {
		return fmt.Errorf("reveal decryption failed: %w", err)
	}

	if len(peerEntropy) != 32 {
		return errors.New("invalid reveal length")
	}

	// Verify commit
	if !VerifyCommit(s.SessionID, peerEntropy, s.koEnhancement.PeerCommit) {
		return errors.New("ko re-enhancement commit verification failed")
	}

	// Determine initiator/responder entropy order
	var rInitiator, rResponder []byte
	if s.isInitiator {
		rInitiator = s.koEnhancement.LocalEntropy
		rResponder = peerEntropy
	} else {
		rInitiator = peerEntropy
		rResponder = s.koEnhancement.LocalEntropy
	}

	// Derive re-enhanced Ko
	s.Ko = DeriveEnhancedKo(s.Ko, rInitiator, rResponder)

	// Zero and clear state
	s.koEnhancement.Zero()
	s.koEnhancement = nil
	s.lastKoEnhancedEpoch = s.Epoch
	s.pendingKoReenhance = false
	ZeroBytes(s.lastSharedSecret)
	s.lastSharedSecret = nil

	return nil
}
