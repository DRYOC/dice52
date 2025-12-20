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

// Send encrypts and sends a message (Section 11)
func (s *Session) Send(pt []byte) (*Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Section 14: Enforce epoch limit
	if s.Ns >= MaxMessagesPerEpoch {
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
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	s.Nr = h.MsgNum + 1
	return pt, nil
}

// applyRatchet performs a PQ ratchet step (Section 13)
func (s *Session) applyRatchet(ss []byte) {
	combined := append(append(s.RK, ss...), s.Ko...)
	s.RK = hkdfExpand(combined, []byte(RKRatchetInfo))
	s.Ko = hkdfExpand(s.RK, []byte(KoInfo))

	s.CKs, s.CKr = InitChainKeys(s.RK, s.Ko)
	s.Ns = 0
	s.Nr = 0
	s.Epoch++
}

// InitiateRatchet starts a PQ ratchet with Dilithium signature
func (s *Session) InitiateRatchet() (*RatchetMessage, error) {
	pub, priv, err := kyber768.Scheme().GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	s.KEMPriv = priv.(*kyber768.PrivateKey)
	s.KEMPub = pub.(*kyber768.PublicKey)

	pubBytes, _ := s.KEMPub.MarshalBinary()
	toSign := append([]byte(SigContext), pubBytes...)
	sig := make([]byte, mode3.SignatureSize)
	mode3.SignTo(s.IDPriv, toSign, sig)

	return &RatchetMessage{
		PubKey: pubBytes,
		Sig:    sig,
	}, nil
}

// RespondRatchet is used to respond to initiator's ratchet message (verify and encapsulate)
func (s *Session) RespondRatchet(msg *RatchetMessage) (*RatchetMessage, error) {
	toVerify := append([]byte(SigContext), msg.PubKey...)
	if !mode3.Verify(s.PeerID, toVerify, msg.Sig) {
		return nil, errors.New("ratchet signature invalid")
	}

	peerPub, err := kyber768.Scheme().UnmarshalBinaryPublicKey(msg.PubKey)
	if err != nil {
		return nil, err
	}

	ct, ss, err := kyber768.Scheme().Encapsulate(peerPub)
	if err != nil {
		return nil, err
	}

	s.applyRatchet(ss)
	return &RatchetMessage{CT: ct}, nil
}

// FinalizeRatchet completes the ratchet on the initiator side
func (s *Session) FinalizeRatchet(msg *RatchetMessage) error {
	ss, err := kyber768.Scheme().Decapsulate(s.KEMPriv, msg.CT)
	if err != nil {
		return err
	}

	s.applyRatchet(ss)
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
		return nil, errors.New("Ko already enhanced")
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
		return errors.New("Ko commit verification failed: reveal does not match commitment")
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

	// Clear enhancement state
	s.koEnhancement = nil
	s.koEnhanced = true

	return nil
}
