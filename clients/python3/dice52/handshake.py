"""Handshake protocol using hybrid KEM (Kyber768 + X25519) and Dilithium3."""

from typing import Tuple

from kyber_py.kyber import Kyber768
from dilithium_py.dilithium import Dilithium3
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from .types import HandshakeMessage, RatchetMessage, SIG_CONTEXT
from .kdf import derive_hybrid_shared_secret
from .error import InvalidHandshakeSignature, KemError


def generate_x25519_keypair() -> Tuple[bytes, bytes]:
    """
    Generate a new X25519 key pair.
    
    Returns:
        Tuple of (public_key, private_key)
    """
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return (
        public_key.public_bytes_raw(),
        private_key.private_bytes_raw()
    )


def x25519_shared_secret(our_priv: bytes, peer_pub: bytes) -> bytes:
    """
    Compute X25519 shared secret.
    
    Args:
        our_priv: Our X25519 private key (32 bytes)
        peer_pub: Peer's X25519 public key (32 bytes)
        
    Returns:
        Shared secret (32 bytes)
    """
    private_key = X25519PrivateKey.from_private_bytes(our_priv)
    public_key = X25519PublicKey.from_public_bytes(peer_pub)
    return private_key.exchange(public_key)


def generate_kem_keypair() -> Tuple[bytes, bytes]:
    """
    Generate a new Kyber768 key pair.
    
    Returns:
        Tuple of (public_key, private_key)
    """
    public_key, private_key = Kyber768.keygen()
    return public_key, private_key


def generate_signing_keypair() -> Tuple[bytes, bytes]:
    """
    Generate a new Dilithium3 key pair.
    
    Returns:
        Tuple of (public_key, private_key)
    """
    public_key, private_key = Dilithium3.keygen()
    return public_key, private_key


def initiator_encapsulate(peer_pub: bytes) -> Tuple[bytes, bytes]:
    """
    Initiator encapsulate: Alice encapsulates to Bob's public key (Section 7).
    
    Args:
        peer_pub: Peer's Kyber public key
        
    Returns:
        Tuple of (shared_secret, ciphertext)
    """
    shared_secret, ciphertext = Kyber768.encaps(peer_pub)
    return shared_secret, ciphertext


def responder_decapsulate(our_priv: bytes, ct: bytes) -> bytes:
    """
    Responder decapsulate: Bob decapsulates using his private key (Section 7).
    
    Args:
        our_priv: Our Kyber private key
        ct: Received ciphertext
        
    Returns:
        Shared secret
    """
    shared_secret = Kyber768.decaps(our_priv, ct)
    return shared_secret


def initiator_handshake(
    peer_kem: bytes,
    peer_ecdh: bytes,
    id_priv: bytes,
) -> Tuple[HandshakeMessage, bytes, bytes]:
    """
    Initiator handshake: hybrid encapsulation to peer's public keys and sign (Section 6.2).
    
    Args:
        peer_kem: Peer's Kyber public key
        peer_ecdh: Peer's X25519 public key
        id_priv: Our Dilithium private key for signing
        
    Returns:
        Tuple of (handshake_message, hybrid_shared_secret, our_ecdh_private_key)
    """
    # Generate ephemeral X25519 key pair
    ecdh_pub, ecdh_priv = generate_x25519_keypair()
    
    # Kyber encapsulation
    ss_pq, ct = initiator_encapsulate(peer_kem)
    
    # X25519 key agreement
    ss_ecdh = x25519_shared_secret(ecdh_priv, peer_ecdh)
    
    # Derive hybrid shared secret
    ss_hybrid = derive_hybrid_shared_secret(ss_pq, ss_ecdh)
    
    # Sign: context || ciphertext || ecdh_pub
    to_sign = SIG_CONTEXT + ct + ecdh_pub
    
    signature = Dilithium3.sign(id_priv, to_sign)
    
    return HandshakeMessage(kyber_ct=ct, ecdh_pub=ecdh_pub, sig=signature), ss_hybrid, ecdh_priv


def responder_handshake(
    msg: HandshakeMessage,
    kem_priv: bytes,
    ecdh_priv: bytes,
    peer_id: bytes,
) -> bytes:
    """
    Responder handshake: verify signature and hybrid decapsulation (Section 6.3).
    
    Args:
        msg: Received handshake message
        kem_priv: Our Kyber private key
        ecdh_priv: Our X25519 private key
        peer_id: Peer's Dilithium public key for verification
        
    Returns:
        Hybrid shared secret
        
    Raises:
        InvalidHandshakeSignature: If signature verification fails
    """
    # Verify signature over context || ciphertext || ecdh_pub
    to_verify = SIG_CONTEXT + msg.kyber_ct + msg.ecdh_pub
    
    if not Dilithium3.verify(peer_id, to_verify, msg.sig):
        raise InvalidHandshakeSignature("Handshake signature verification failed")
    
    # Decapsulate Kyber
    ss_pq = responder_decapsulate(kem_priv, msg.kyber_ct)
    
    # X25519 key agreement
    ss_ecdh = x25519_shared_secret(ecdh_priv, msg.ecdh_pub)
    
    # Derive hybrid shared secret
    ss_hybrid = derive_hybrid_shared_secret(ss_pq, ss_ecdh)
    
    return ss_hybrid


def initiator_hybrid_encapsulate(peer_kem: bytes, peer_ecdh: bytes) -> Tuple[bytes, bytes, bytes, bytes]:
    """
    Initiator hybrid encapsulate: Alice encapsulates to Bob's public keys.
    
    Args:
        peer_kem: Peer's Kyber public key
        peer_ecdh: Peer's X25519 public key
        
    Returns:
        Tuple of (hybrid_shared_secret, kyber_ciphertext, our_ecdh_pub, our_ecdh_priv)
    """
    # Generate ephemeral X25519 key pair
    ecdh_pub, ecdh_priv = generate_x25519_keypair()
    
    # Kyber encapsulation
    ss_pq, ct = initiator_encapsulate(peer_kem)
    
    # X25519 key agreement
    ss_ecdh = x25519_shared_secret(ecdh_priv, peer_ecdh)
    
    # Derive hybrid shared secret
    ss_hybrid = derive_hybrid_shared_secret(ss_pq, ss_ecdh)
    
    return ss_hybrid, ct, ecdh_pub, ecdh_priv


def responder_hybrid_decapsulate(
    kem_priv: bytes,
    ecdh_priv: bytes,
    kyber_ct: bytes,
    peer_ecdh_pub: bytes
) -> bytes:
    """
    Responder hybrid decapsulate: Bob decapsulates using his private keys.
    
    Args:
        kem_priv: Our Kyber private key
        ecdh_priv: Our X25519 private key
        kyber_ct: Received Kyber ciphertext
        peer_ecdh_pub: Peer's X25519 public key
        
    Returns:
        Hybrid shared secret
    """
    # Decapsulate Kyber
    ss_pq = responder_decapsulate(kem_priv, kyber_ct)
    
    # X25519 key agreement
    ss_ecdh = x25519_shared_secret(ecdh_priv, peer_ecdh_pub)
    
    # Derive hybrid shared secret
    ss_hybrid = derive_hybrid_shared_secret(ss_pq, ss_ecdh)
    
    return ss_hybrid
