"""Key derivation functions using HKDF-SHA256."""

import hashlib
import hmac
from typing import Tuple

from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF

from .types import (
    KEY_LEN,
    RK_INFO,
    KO_INFO,
    CKS_INFO,
    CKR_INFO,
    MK_INFO,
    RK_RATCHET_INFO,
    HYBRID_SS_INFO,
    KO_COMMIT_PREFIX,
    KO_COMMIT_KEY_INFO,
    KO_ENHANCED_INFO,
)


def hkdf_expand(secret: bytes, info: bytes, length: int = KEY_LEN) -> bytes:
    """Derive a key using HKDF-SHA256 (Section 3.2)."""
    return HKDF(secret, length, salt=b"", num_keys=1, hashmod=SHA256, context=info)


def hkdf_expand_with_salt(secret: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF expand with salt."""
    return HKDF(secret, length, salt=salt, num_keys=1, hashmod=SHA256, context=info)


def derive_hybrid_shared_secret(ss_pq: bytes, ss_ecdh: bytes) -> bytes:
    """
    Derive hybrid shared secret from Kyber and X25519 shared secrets (Section 3.1).
    
    SS_hybrid = HKDF(SS_pq || SS_ecdh, "Dice52-Hybrid-SS")
    
    Args:
        ss_pq: Post-quantum (Kyber) shared secret
        ss_ecdh: Classical (X25519) shared secret
        
    Returns:
        Combined hybrid shared secret
    """
    combined = ss_pq + ss_ecdh
    return hkdf_expand(combined, HYBRID_SS_INFO)


def derive_initial_keys(ss: bytes) -> Tuple[bytes, bytes]:
    """
    Derive RK and Ko from shared secret (Section 8).
    
    Args:
        ss: Shared secret from KEM
        
    Returns:
        Tuple of (root_key, ko)
    """
    rk = hkdf_expand(ss, RK_INFO)
    ko = hkdf_expand(rk, KO_INFO)
    return rk, ko


def init_chain_keys(rk: bytes, ko: bytes) -> Tuple[bytes, bytes]:
    """
    Initialize CKs and CKr from RK and Ko (Section 9).
    
    Args:
        rk: Root key
        ko: Ko value
        
    Returns:
        Tuple of (chain_key_send, chain_key_receive)
    """
    # CKs = HKDF(RK, "Dice52-CKs" || Ko)
    cks = hkdf_expand(rk, CKS_INFO + ko)
    # CKr = HKDF(RK, "Dice52-CKr" || Ko)
    ckr = hkdf_expand(rk, CKR_INFO + ko)
    return cks, ckr


def ratchet_rk(old_rk: bytes, ss: bytes, ko: bytes) -> bytes:
    """
    Perform a PQ ratchet step (Section 13.2).
    
    Args:
        old_rk: Previous root key
        ss: New shared secret from ratchet
        ko: Current Ko value
        
    Returns:
        New root key
    """
    # RK = HKDF(RK || SS || Ko, "Dice52-RK-Ratchet")
    combined = old_rk + ss + ko
    return hkdf_expand(combined, RK_RATCHET_INFO)


def ck_to_mk(ck: bytes, ko: bytes, n: int, dir_byte: int, salt: bytes) -> Tuple[bytes, bytes]:
    """
    Derive the next chain key and message key (Section 10).
    
    CK_next || MK = HKDF(CK, "Dice52-MK" || Ko || dir || n)
    
    Args:
        ck: Current chain key
        ko: Ko value
        n: Message number
        dir_byte: Direction byte
        salt: Salt (typically RK)
        
    Returns:
        Tuple of (next_chain_key, message_key)
    """
    # Build info: MK_INFO || Ko || dir || n (8 bytes big-endian)
    info = MK_INFO + ko + bytes([dir_byte]) + n.to_bytes(8, 'big')
    
    out = hkdf_expand_with_salt(ck, salt, info, 64)
    
    return out[:32], out[32:]


# ============================================================================
# Ko Enhancement Functions (Section 7.1)
# ============================================================================

def derive_ko_commit_key(ss: bytes) -> bytes:
    """
    Derive the temporary key for Ko enhancement commit/reveal encryption.
    
    Args:
        ss: Shared secret from initial handshake
        
    Returns:
        Temporary key for encrypting commits and reveals
    """
    return hkdf_expand(ss, KO_COMMIT_KEY_INFO)


def commit_entropy(session_id: int, entropy: bytes) -> bytes:
    """
    Create a commitment to entropy (Section 7.1.2).
    
    Args:
        session_id: Session identifier
        entropy: Local random entropy (32 bytes)
        
    Returns:
        SHA-256 commitment
    """
    h = hashlib.sha256()
    h.update(KO_COMMIT_PREFIX)
    h.update(session_id.to_bytes(4, 'big'))
    h.update(entropy)
    return h.digest()


def verify_commit(session_id: int, entropy: bytes, commit: bytes) -> bool:
    """
    Verify an entropy commitment (Section 7.1.3).
    
    Args:
        session_id: Session identifier
        entropy: Revealed entropy
        commit: Previously received commitment
        
    Returns:
        True if commitment is valid
    """
    expected = commit_entropy(session_id, entropy)
    return hmac.compare_digest(expected, commit)


def derive_enhanced_ko(ko_base: bytes, r_initiator: bytes, r_responder: bytes) -> bytes:
    """
    Derive enhanced Ko with contributed entropy from both parties (Section 7.1.4).
    
    Args:
        ko_base: Original Ko derived from handshake
        r_initiator: Initiator's random contribution
        r_responder: Responder's random contribution
        
    Returns:
        Enhanced Ko with independent entropy
    """
    combined = ko_base + r_initiator + r_responder
    return hkdf_expand(combined, KO_ENHANCED_INFO)

