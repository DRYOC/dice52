"""Session management for Dice52 protocol."""

import base64
import threading
from typing import Optional, Tuple

from kyber_py.kyber import Kyber768
from dilithium_py.dilithium import Dilithium3
from Crypto.Cipher import ChaCha20_Poly1305

from .types import (
    VERSION,
    DEFAULT_MAX_MESSAGES_PER_EPOCH,
    KO_INFO,
    RK_RATCHET_INFO,
    SIG_CONTEXT,
    ParanoidConfig,
    Message,
    Header,
    RatchetMessage,
    KoCommitMessage,
    KoRevealMessage,
    KoEnhancementState,
)
from .crypto import encrypt, decrypt, rand_bytes, zero_bytes
from .kdf import (
    ck_to_mk,
    init_chain_keys,
    hkdf_expand,
    derive_ko_commit_key,
    commit_entropy,
    verify_commit,
    derive_enhanced_ko,
)
from .handshake import generate_kem_keypair
from .error import (
    Dice52Error,
    EpochExhausted,
    EpochMismatch,
    ReplayDetected,
    InvalidRatchetSignature,
    KemError,
    KoEnhancementError,
    KoCommitMismatch,
    ConfigError,
)


class Session:
    """Session state for a Dice52 PQ ratchet session."""
    
    def __init__(
        self,
        session_id: int,
        rk: bytes,
        ko: bytes,
        cks: bytes,
        ckr: bytes,
        kem_pub: bytes,
        kem_priv: bytes,
        id_pub: bytes,
        id_priv: bytes,
        peer_id: bytes,
        is_initiator: bool = True,
    ):
        """
        Create a new session with the given parameters.
        
        Args:
            session_id: Unique session identifier
            rk: Root key
            ko: Ordering key
            cks: Sending chain key
            ckr: Receiving chain key
            kem_pub: Our KEM public key
            kem_priv: Our KEM private key
            id_pub: Our identity public key
            id_priv: Our identity private key
            peer_id: Peer's identity public key
            is_initiator: Whether this session is the initiator
        """
        self._lock = threading.Lock()
        
        self._rk = rk
        self._ko = ko
        self._cks = cks
        self._ckr = ckr
        
        self._ns: int = 0
        self._nr: int = 0
        self._epoch: int = 0
        
        self._kem_pub = kem_pub
        self._kem_priv = kem_priv
        self._id_pub = id_pub
        self._id_priv = id_priv
        self._peer_id = peer_id
        
        self._session_id = session_id
        
        self._ko_enhancement: Optional[KoEnhancementState] = None
        self._ko_enhanced: bool = False
        self._is_initiator = is_initiator
        
        self._paranoid_config = ParanoidConfig()
        self._last_ko_enhanced_epoch: int = 0
        self._pending_ko_reenhance: bool = False
        self._last_shared_secret: Optional[bytes] = None
    
    def set_paranoid_mode(self, config: ParanoidConfig) -> None:
        """Enable paranoid mode with the given configuration."""
        config.validate()
        with self._lock:
            self._paranoid_config = config
    
    def get_paranoid_config(self) -> ParanoidConfig:
        """Get the current paranoid mode configuration."""
        with self._lock:
            return self._paranoid_config
    
    def is_paranoid_mode(self) -> bool:
        """Check if paranoid mode is enabled."""
        with self._lock:
            return self._paranoid_config.enabled
    
    def needs_ko_reenhancement(self) -> bool:
        """Check if Ko re-enhancement is pending."""
        with self._lock:
            return self._pending_ko_reenhance
    
    def _get_max_messages_per_epoch(self) -> int:
        """Get the effective max messages per epoch."""
        if self._paranoid_config.enabled and self._paranoid_config.max_messages_per_epoch > 0:
            return self._paranoid_config.max_messages_per_epoch
        return DEFAULT_MAX_MESSAGES_PER_EPOCH
    
    def send(self, pt: bytes) -> Message:
        """
        Send encrypts and sends a message (Section 11).
        
        Args:
            pt: Plaintext to send
            
        Returns:
            Encrypted message
            
        Raises:
            EpochExhausted: If epoch message limit reached
        """
        with self._lock:
            # Section 14: Enforce epoch limit (configurable in paranoid mode)
            max_messages = self._get_max_messages_per_epoch()
            if self._ns >= max_messages:
                raise EpochExhausted("Epoch exhausted: rekey required")
            
            next_ck, mk = ck_to_mk(self._cks, self._ko, self._ns, 0, self._rk)
            self._cks = next_ck
            
            # Section 11.1: AD must include version, epoch, message number, direction
            header = Header(
                version=VERSION,
                epoch=self._epoch,
                msg_num=self._ns,
                direction="send",
            )
            ad = header.to_json()
            
            ct = encrypt(mk, self._session_id, self._epoch, self._ns, ad, pt)
            # Note: Python doesn't guarantee secure zeroing, but clear anyway
            mk = bytes(len(mk))
            self._ns += 1
            
            return Message(
                header=base64.b64encode(ad).decode('ascii'),
                body=base64.b64encode(ct).decode('ascii'),
            )
    
    def receive(self, msg: Message) -> bytes:
        """
        Receive decrypts a received message (Section 12).
        
        Args:
            msg: Encrypted message to receive
            
        Returns:
            Decrypted plaintext
            
        Raises:
            EpochMismatch: If message epoch doesn't match session
            ReplayDetected: If message number is too low
        """
        with self._lock:
            ad = base64.b64decode(msg.header)
            header = Header.from_json(ad)
            
            # Section 16: Message numbers must be monotonically increasing
            if header.msg_num < self._nr:
                raise ReplayDetected("Message number too low")
            
            ct = base64.b64decode(msg.body)
            
            # Enforce epoch match on receive
            if header.epoch != self._epoch:
                raise EpochMismatch("Epoch mismatch")
            
            # Derive MK using message number from header (use dir=0 to match sender)
            next_ck, mk = ck_to_mk(self._ckr, self._ko, header.msg_num, 0, self._rk)
            self._ckr = next_ck
            
            # Reconstruct AD with send direction for decryption (match sender's AD)
            recv_header = Header(
                version=header.version,
                epoch=header.epoch,
                msg_num=header.msg_num,
                direction="send",  # Match sender's AD
            )
            recv_ad = recv_header.to_json()
            
            pt = decrypt(mk, self._session_id, header.epoch, header.msg_num, recv_ad, ct)
            mk = bytes(len(mk))
            
            self._nr = header.msg_num + 1
            return pt
    
    def _apply_ratchet(self, ss: bytes) -> None:
        """Internal ratchet application."""
        # RK = HKDF(RK || SS || Ko, "Dice52-RK-Ratchet")
        combined = self._rk + ss + self._ko
        self._rk = hkdf_expand(combined, RK_RATCHET_INFO)
        
        # Ko = HKDF(RK, "Dice52-Ko")
        self._ko = hkdf_expand(self._rk, KO_INFO)
        
        # Reinitialize chain keys
        self._cks, self._ckr = init_chain_keys(self._rk, self._ko)
        self._ns = 0
        self._nr = 0
        self._epoch += 1
        
        # Paranoid mode: Check if Ko re-enhancement is needed (Section 7.2)
        if self._paranoid_config.enabled and self._paranoid_config.ko_reenhance_interval > 0:
            epochs_since_last_enhance = self._epoch - self._last_ko_enhanced_epoch
            if epochs_since_last_enhance >= self._paranoid_config.ko_reenhance_interval:
                self._pending_ko_reenhance = True
                # Store shared secret for re-enhancement
                self._last_shared_secret = ss
    
    def initiate_ratchet(self) -> RatchetMessage:
        """Initiate a PQ ratchet with Dilithium signature."""
        with self._lock:
            self._kem_pub, self._kem_priv = generate_kem_keypair()
            
            # Sign: context || public key
            to_sign = SIG_CONTEXT + self._kem_pub
            
            signature = Dilithium3.sign(self._id_priv, to_sign)
            
            return RatchetMessage(
                pub_key=self._kem_pub,
                sig=signature,
                ct=None,
            )
    
    def respond_ratchet(self, msg: RatchetMessage) -> RatchetMessage:
        """Respond to initiator's ratchet message (verify and encapsulate)."""
        with self._lock:
            if msg.pub_key is None or msg.sig is None:
                raise KemError("Missing public key or signature in ratchet message")
            
            # Verify signature
            to_verify = SIG_CONTEXT + msg.pub_key
            
            if not Dilithium3.verify(self._peer_id, to_verify, msg.sig):
                raise InvalidRatchetSignature("Ratchet signature verification failed")
            
            # Encapsulate to peer's new public key
            shared_secret, ciphertext = Kyber768.encaps(msg.pub_key)
            
            # Apply ratchet
            self._apply_ratchet(shared_secret)
            
            # Responder needs chain keys swapped relative to initiator
            self._cks, self._ckr = self._ckr, self._cks
            
            return RatchetMessage(
                pub_key=None,
                sig=None,
                ct=ciphertext,
            )
    
    def finalize_ratchet(self, msg: RatchetMessage) -> None:
        """Finalize the ratchet on the initiator side."""
        with self._lock:
            if msg.ct is None:
                raise KemError("Missing ciphertext in ratchet message")
            
            shared_secret = Kyber768.decaps(self._kem_priv, msg.ct)
            
            self._apply_ratchet(shared_secret)
    
    @property
    def epoch(self) -> int:
        """Get current epoch."""
        with self._lock:
            return self._epoch
    
    @property
    def session_id(self) -> int:
        """Get session ID."""
        return self._session_id
    
    def is_ko_enhanced(self) -> bool:
        """Check if Ko has been enhanced."""
        with self._lock:
            return self._ko_enhanced
    
    # =========================================================================
    # Ko Enhancement Protocol (Section 7.1)
    # =========================================================================
    
    def ko_start_enhancement(self, ss: bytes) -> KoCommitMessage:
        """
        Start Ko enhancement: generate local entropy and create commit message.
        
        Args:
            ss: Original shared secret from handshake (for deriving TK)
            
        Returns:
            Commit message to send to peer
        """
        with self._lock:
            if self._ko_enhanced:
                raise KoEnhancementError("Ko already enhanced")
            
            # Generate local entropy
            local_entropy = rand_bytes(32)
            
            # Derive temporary key
            tk = derive_ko_commit_key(ss)
            
            # Create commitment
            local_commit = commit_entropy(self._session_id, local_entropy)
            
            # Encrypt commitment with TK (nonce = 0 for commit)
            nonce = bytes(12)  # All zeros for commit
            cipher = ChaCha20_Poly1305.new(key=tk, nonce=nonce)
            cipher.update(b"ko-commit")
            commit_ct, tag = cipher.encrypt_and_digest(local_commit)
            commit_ct = commit_ct + tag
            
            # Store state
            self._ko_enhancement = KoEnhancementState(
                tk=tk,
                local_entropy=local_entropy,
                local_commit=local_commit,
            )
            
            return KoCommitMessage(commit_ct=commit_ct)
    
    def ko_process_commit(self, peer_commit_msg: KoCommitMessage) -> KoRevealMessage:
        """
        Process received commit and create reveal message.
        
        Args:
            peer_commit_msg: Commit message received from peer
            
        Returns:
            Reveal message to send to peer
        """
        with self._lock:
            if self._ko_enhancement is None:
                raise KoEnhancementError("Enhancement not started")
            
            state = self._ko_enhancement
            
            # Decrypt peer's commit
            nonce = bytes(12)  # All zeros for commit
            ct = peer_commit_msg.commit_ct[:-16]
            tag = peer_commit_msg.commit_ct[-16:]
            cipher = ChaCha20_Poly1305.new(key=state.tk, nonce=nonce)
            cipher.update(b"ko-commit")
            try:
                peer_commit = cipher.decrypt_and_verify(ct, tag)
            except ValueError as e:
                raise KoEnhancementError(f"Commit decryption failed: {e}")
            
            if len(peer_commit) != 32:
                raise KoEnhancementError("Invalid commit length")
            
            state.peer_commit = peer_commit
            
            # Create reveal (encrypt our entropy with nonce = 1)
            reveal_nonce = bytes(11) + bytes([1])
            cipher = ChaCha20_Poly1305.new(key=state.tk, nonce=reveal_nonce)
            cipher.update(b"ko-reveal")
            reveal_ct, tag = cipher.encrypt_and_digest(state.local_entropy)
            reveal_ct = reveal_ct + tag
            
            return KoRevealMessage(reveal_ct=reveal_ct)
    
    def ko_finalize(self, peer_reveal_msg: KoRevealMessage) -> None:
        """
        Finalize Ko enhancement with peer's reveal.
        
        Args:
            peer_reveal_msg: Reveal message received from peer
        """
        with self._lock:
            if self._ko_enhancement is None:
                raise KoEnhancementError("Enhancement not started")
            
            state = self._ko_enhancement
            
            if state.peer_commit is None:
                raise KoEnhancementError("Peer commit not received")
            
            # Decrypt peer's reveal
            reveal_nonce = bytes(11) + bytes([1])
            ct = peer_reveal_msg.reveal_ct[:-16]
            tag = peer_reveal_msg.reveal_ct[-16:]
            cipher = ChaCha20_Poly1305.new(key=state.tk, nonce=reveal_nonce)
            cipher.update(b"ko-reveal")
            try:
                peer_entropy = cipher.decrypt_and_verify(ct, tag)
            except ValueError as e:
                raise KoEnhancementError(f"Reveal decryption failed: {e}")
            
            if len(peer_entropy) != 32:
                raise KoEnhancementError("Invalid reveal length")
            
            # Verify commit
            if not verify_commit(self._session_id, peer_entropy, state.peer_commit):
                raise KoCommitMismatch("Ko commit verification failed")
            
            # Determine initiator/responder entropy order
            if self._is_initiator:
                r_initiator = state.local_entropy
                r_responder = peer_entropy
            else:
                r_initiator = peer_entropy
                r_responder = state.local_entropy
            
            # Derive enhanced Ko
            self._ko = derive_enhanced_ko(self._ko, r_initiator, r_responder)
            
            # Clear sensitive state
            state.zero()
            self._ko_enhancement = None
            self._ko_enhanced = True
            
            # Track when Ko was last enhanced (for paranoid mode)
            self._last_ko_enhanced_epoch = self._epoch
            self._pending_ko_reenhance = False
    
    # =========================================================================
    # Paranoid Mode Ko Re-enhancement (Section 7.2)
    # =========================================================================
    
    def ko_start_reenhancement(self) -> KoCommitMessage:
        """
        Start Ko re-enhancement during paranoid mode.
        This should be called after a ratchet when needs_ko_reenhancement() returns true.
        """
        with self._lock:
            if not self._paranoid_config.enabled:
                raise KoEnhancementError("Paranoid mode not enabled")
            
            if not self._pending_ko_reenhance:
                raise KoEnhancementError("Ko re-enhancement not needed")
            
            if self._last_shared_secret is None:
                raise KoEnhancementError("No shared secret available for re-enhancement")
            
            # Generate local entropy
            local_entropy = rand_bytes(32)
            
            # Derive temporary key from the ratchet shared secret
            tk = derive_ko_commit_key(self._last_shared_secret)
            
            # Create commitment
            local_commit = commit_entropy(self._session_id, local_entropy)
            
            # Encrypt commitment with TK (nonce = 0 for commit)
            nonce = bytes(12)
            cipher = ChaCha20_Poly1305.new(key=tk, nonce=nonce)
            cipher.update(b"ko-reenhance-commit")
            commit_ct, tag = cipher.encrypt_and_digest(local_commit)
            commit_ct = commit_ct + tag
            
            # Store state
            self._ko_enhancement = KoEnhancementState(
                tk=tk,
                local_entropy=local_entropy,
                local_commit=local_commit,
            )
            
            return KoCommitMessage(commit_ct=commit_ct)
    
    def ko_process_reenhance_commit(self, peer_commit_msg: KoCommitMessage) -> KoRevealMessage:
        """Process received re-enhancement commit."""
        with self._lock:
            if self._ko_enhancement is None:
                raise KoEnhancementError("Re-enhancement not started")
            
            state = self._ko_enhancement
            
            # Decrypt peer's commit
            nonce = bytes(12)
            ct = peer_commit_msg.commit_ct[:-16]
            tag = peer_commit_msg.commit_ct[-16:]
            cipher = ChaCha20_Poly1305.new(key=state.tk, nonce=nonce)
            cipher.update(b"ko-reenhance-commit")
            try:
                peer_commit = cipher.decrypt_and_verify(ct, tag)
            except ValueError as e:
                raise KoEnhancementError(f"Commit decryption failed: {e}")
            
            if len(peer_commit) != 32:
                raise KoEnhancementError("Invalid commit length")
            
            state.peer_commit = peer_commit
            
            # Create reveal (encrypt our entropy with nonce = 1)
            reveal_nonce = bytes(11) + bytes([1])
            cipher = ChaCha20_Poly1305.new(key=state.tk, nonce=reveal_nonce)
            cipher.update(b"ko-reenhance-reveal")
            reveal_ct, tag = cipher.encrypt_and_digest(state.local_entropy)
            reveal_ct = reveal_ct + tag
            
            return KoRevealMessage(reveal_ct=reveal_ct)
    
    def ko_finalize_reenhancement(self, peer_reveal_msg: KoRevealMessage) -> None:
        """Finalize Ko re-enhancement."""
        with self._lock:
            if self._ko_enhancement is None:
                raise KoEnhancementError("Re-enhancement not started")
            
            state = self._ko_enhancement
            
            if state.peer_commit is None:
                raise KoEnhancementError("Peer commit not received")
            
            # Decrypt peer's reveal
            reveal_nonce = bytes(11) + bytes([1])
            ct = peer_reveal_msg.reveal_ct[:-16]
            tag = peer_reveal_msg.reveal_ct[-16:]
            cipher = ChaCha20_Poly1305.new(key=state.tk, nonce=reveal_nonce)
            cipher.update(b"ko-reenhance-reveal")
            try:
                peer_entropy = cipher.decrypt_and_verify(ct, tag)
            except ValueError as e:
                raise KoEnhancementError(f"Reveal decryption failed: {e}")
            
            if len(peer_entropy) != 32:
                raise KoEnhancementError("Invalid reveal length")
            
            # Verify commit
            if not verify_commit(self._session_id, peer_entropy, state.peer_commit):
                raise KoCommitMismatch("Ko re-enhancement commit verification failed")
            
            # Determine initiator/responder entropy order
            if self._is_initiator:
                r_initiator = state.local_entropy
                r_responder = peer_entropy
            else:
                r_initiator = peer_entropy
                r_responder = state.local_entropy
            
            # Derive re-enhanced Ko
            self._ko = derive_enhanced_ko(self._ko, r_initiator, r_responder)
            
            # Clear state
            state.zero()
            self._ko_enhancement = None
            self._last_ko_enhanced_epoch = self._epoch
            self._pending_ko_reenhance = False
            self._last_shared_secret = None
