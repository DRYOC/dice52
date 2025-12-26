"""Handshake protocol using Kyber768 and Dilithium3."""

from typing import Tuple

from kyber_py.kyber import Kyber768
from dilithium_py.dilithium import Dilithium3

from .types import HandshakeMessage, SIG_CONTEXT
from .error import InvalidHandshakeSignature, KemError


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
    id_priv: bytes,
) -> Tuple[HandshakeMessage, bytes]:
    """
    Initiator handshake: encapsulate to peer's KEM public key and sign.
    
    Args:
        peer_kem: Peer's Kyber public key
        id_priv: Our Dilithium private key for signing
        
    Returns:
        Tuple of (handshake_message, shared_secret)
    """
    # Encapsulate to peer's public key
    ss, ct = initiator_encapsulate(peer_kem)
    
    # Sign: context || ciphertext
    to_sign = SIG_CONTEXT + ct
    
    signature = Dilithium3.sign(id_priv, to_sign)
    
    return HandshakeMessage(kyber_ct=ct, sig=signature), ss


def responder_handshake(
    msg: HandshakeMessage,
    kem_priv: bytes,
    peer_id: bytes,
) -> bytes:
    """
    Responder handshake: verify signature and decapsulate.
    
    Args:
        msg: Received handshake message
        kem_priv: Our Kyber private key
        peer_id: Peer's Dilithium public key for verification
        
    Returns:
        Shared secret
        
    Raises:
        InvalidHandshakeSignature: If signature verification fails
    """
    # Verify signature
    to_verify = SIG_CONTEXT + msg.kyber_ct
    
    if not Dilithium3.verify(peer_id, to_verify, msg.sig):
        raise InvalidHandshakeSignature("Handshake signature verification failed")
    
    # Decapsulate
    return responder_decapsulate(kem_priv, msg.kyber_ct)
