"""
Dice52-PQ: Post-Quantum Ratcheting Protocol

A quantum-safe ratchet protocol using hybrid KEM (ML-KEM + X25519) for key
encapsulation and ML-DSA (Dilithium) for signatures.

Features:
- Hybrid KEM: Combines Kyber768 (post-quantum) with X25519 (classical)
- Post-quantum signatures using Dilithium3
- Forward secrecy via ratcheting
- Per-message fresh keys
- ChaCha20-Poly1305 AEAD encryption

The hybrid KEM ensures that the shared secret remains secure provided
at least one of the component KEMs remains secure.
"""

from .types import (
    VERSION,
    KEY_LEN,
    DEFAULT_MAX_MESSAGES_PER_EPOCH,
    RK_INFO,
    KO_INFO,
    CKS_INFO,
    CKR_INFO,
    MK_INFO,
    RK_RATCHET_INFO,
    HYBRID_SS_INFO,
    X25519_PUBLIC_KEY_SIZE,
    X25519_PRIVATE_KEY_SIZE,
    KO_COMMIT_PREFIX,
    KO_COMMIT_KEY_INFO,
    KO_ENHANCED_INFO,
    SIG_CONTEXT,
    ParanoidConfig,
    HandshakeMessage,
    Message,
    RatchetMessage,
    Header,
    KoCommitMessage,
    KoRevealMessage,
)
from .crypto import encrypt, decrypt, rand_bytes, zero_bytes
from .kdf import (
    derive_initial_keys,
    init_chain_keys,
    ratchet_rk,
    ck_to_mk,
    derive_ko_commit_key,
    commit_entropy,
    verify_commit,
    derive_enhanced_ko,
    derive_hybrid_shared_secret,
)
from .handshake import (
    generate_kem_keypair,
    generate_signing_keypair,
    generate_x25519_keypair,
    initiator_encapsulate,
    responder_decapsulate,
    initiator_handshake,
    responder_handshake,
    initiator_hybrid_encapsulate,
    responder_hybrid_decapsulate,
    x25519_shared_secret,
)
from .session import Session
from .error import Dice52Error

__version__ = "0.1.0"
__all__ = [
    # Constants
    "VERSION",
    "KEY_LEN",
    "DEFAULT_MAX_MESSAGES_PER_EPOCH",
    "RK_INFO",
    "KO_INFO",
    "CKS_INFO",
    "CKR_INFO",
    "MK_INFO",
    "RK_RATCHET_INFO",
    "HYBRID_SS_INFO",
    "X25519_PUBLIC_KEY_SIZE",
    "X25519_PRIVATE_KEY_SIZE",
    "KO_COMMIT_PREFIX",
    "KO_COMMIT_KEY_INFO",
    "KO_ENHANCED_INFO",
    "SIG_CONTEXT",
    # Types
    "ParanoidConfig",
    "HandshakeMessage",
    "Message",
    "RatchetMessage",
    "Header",
    "KoCommitMessage",
    "KoRevealMessage",
    # Crypto
    "encrypt",
    "decrypt",
    "rand_bytes",
    "zero_bytes",
    # KDF
    "derive_initial_keys",
    "init_chain_keys",
    "ratchet_rk",
    "ck_to_mk",
    "derive_ko_commit_key",
    "commit_entropy",
    "verify_commit",
    "derive_enhanced_ko",
    "derive_hybrid_shared_secret",
    # Handshake
    "generate_kem_keypair",
    "generate_signing_keypair",
    "generate_x25519_keypair",
    "initiator_encapsulate",
    "responder_decapsulate",
    "initiator_handshake",
    "responder_handshake",
    "initiator_hybrid_encapsulate",
    "responder_hybrid_decapsulate",
    "x25519_shared_secret",
    # Session
    "Session",
    # Error
    "Dice52Error",
]

