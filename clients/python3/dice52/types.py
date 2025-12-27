"""Constants and types for the Dice52 protocol."""

from dataclasses import dataclass, field
from typing import Optional
import json


# Protocol version
VERSION: int = 1

# Key length in bytes
KEY_LEN: int = 32

# Section 14: Default maximum messages per epoch
DEFAULT_MAX_MESSAGES_PER_EPOCH: int = 33

# Protocol-specified info strings (Section 8, 9, 10)
RK_INFO: bytes = b"Dice52-RK"
KO_INFO: bytes = b"Dice52-Ko"
CKS_INFO: bytes = b"Dice52-CKs"
CKR_INFO: bytes = b"Dice52-CKr"
MK_INFO: bytes = b"Dice52-MK"

# Ratchet info (Section 13)
RK_RATCHET_INFO: bytes = b"Dice52-RK-Ratchet"

# Hybrid KEM info string (Section 3.4)
HYBRID_SS_INFO: bytes = b"Dice52-Hybrid-SS"

# X25519 key sizes
X25519_PUBLIC_KEY_SIZE: int = 32
X25519_PRIVATE_KEY_SIZE: int = 32

# Ko enhancement info strings (Section 7.1)
KO_COMMIT_PREFIX: bytes = b"Dice52-Ko-Commit"
KO_COMMIT_KEY_INFO: bytes = b"Dice52-Ko-CommitKey"
KO_ENHANCED_INFO: bytes = b"Dice52-Ko-Enhanced"

# Signature context (Section 4)
SIG_CONTEXT: bytes = b"Dice52-PQ-Signature"


@dataclass
class ParanoidConfig:
    """Paranoid mode configuration (Section 7.2)."""
    
    enabled: bool = False
    ko_reenhance_interval: int = 0  # 0 = never re-enhance after initial
    max_messages_per_epoch: int = DEFAULT_MAX_MESSAGES_PER_EPOCH
    
    @classmethod
    def default(cls) -> "ParanoidConfig":
        """Return a sensible default paranoid configuration."""
        return cls(
            enabled=True,
            ko_reenhance_interval=10,  # Re-enhance Ko every 10 epochs
            max_messages_per_epoch=16,  # Reduced from 33 to 16
        )
    
    def validate(self) -> None:
        """Validate the configuration, raises ValueError if invalid."""
        if self.max_messages_per_epoch < 1:
            raise ValueError("max_messages_per_epoch must be >= 1")
        if self.max_messages_per_epoch > 33:
            raise ValueError("max_messages_per_epoch must be <= 33")


@dataclass
class HandshakeMessage:
    """Handshake message for initial key exchange (Section 6.2).
    Now includes X25519 public key for hybrid KEM.
    """
    
    kyber_ct: bytes  # Kyber ciphertext
    ecdh_pub: bytes  # X25519 ephemeral public key (32 bytes)
    sig: bytes  # Dilithium signature over kyber_ct || ecdh_pub


@dataclass
class Message:
    """Encrypted message with header and body."""
    
    header: str  # Base64-encoded header (JSON)
    body: str  # Base64-encoded ciphertext


@dataclass
class RatchetMessage:
    """Ratchet message for hybrid PQ ratchet key exchange (Section 12)."""
    
    pub_key: Optional[bytes] = None  # New KEM public key (for initiator)
    ecdh_pub: Optional[bytes] = None  # X25519 public key (32 bytes)
    sig: Optional[bytes] = None  # Dilithium signature over pub_key || ecdh_pub
    ct: Optional[bytes] = None  # KEM ciphertext (for responder)


@dataclass
class Header:
    """Header includes all AD fields required by Section 11.1."""
    
    version: int  # Protocol version
    epoch: int  # Epoch number
    msg_num: int  # Message number
    direction: str  # Direction ("send" or "receive")
    
    def to_json(self) -> bytes:
        """Serialize header to JSON bytes."""
        return json.dumps({
            "v": self.version,
            "e": self.epoch,
            "n": self.msg_num,
            "d": self.direction,
        }).encode()
    
    @classmethod
    def from_json(cls, data: bytes) -> "Header":
        """Deserialize header from JSON bytes."""
        d = json.loads(data)
        return cls(
            version=d["v"],
            epoch=d["e"],
            msg_num=d["n"],
            direction=d["d"],
        )


@dataclass
class KoCommitMessage:
    """Ko enhancement commit message (Section 7.1.2)."""
    
    commit_ct: bytes  # Encrypted SHA-256 commitment to local entropy


@dataclass
class KoRevealMessage:
    """Ko enhancement reveal message (Section 7.1.3)."""
    
    reveal_ct: bytes  # Encrypted local entropy value


@dataclass
class KoEnhancementState:
    """State for Ko enhancement protocol."""
    
    tk: bytes  # Temporary key for commit/reveal encryption
    local_entropy: bytes  # Our local entropy
    local_commit: bytes  # Our commitment
    peer_commit: Optional[bytes] = None  # Peer's commitment (set after receiving)
    peer_entropy: Optional[bytes] = None  # Peer's entropy (set after reveal)
    
    def zero(self) -> None:
        """Securely clear all sensitive data."""
        # Note: Python doesn't guarantee memory clearing, but we overwrite anyway
        if self.tk:
            self.tk = bytes(len(self.tk))
        if self.local_entropy:
            self.local_entropy = bytes(len(self.local_entropy))
        if self.local_commit:
            self.local_commit = bytes(len(self.local_commit))
        if self.peer_commit:
            self.peer_commit = bytes(len(self.peer_commit))
        if self.peer_entropy:
            self.peer_entropy = bytes(len(self.peer_entropy))

