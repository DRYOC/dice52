"""Cryptographic operations using ChaCha20-Poly1305."""

import os
import struct
from typing import Tuple

from Crypto.Cipher import ChaCha20_Poly1305

from .error import DecryptionFailed


def rand_bytes(n: int) -> bytes:
    """Generate n random bytes using OS-provided secure random."""
    return os.urandom(n)


def zero_bytes(data: bytearray) -> None:
    """
    Securely zero a bytearray to prevent sensitive data from lingering in memory.
    Note: Python doesn't guarantee memory clearing, but we overwrite anyway.
    """
    for i in range(len(data)):
        data[i] = 0


def make_nonce(sid: int, epoch: int, ctr: int) -> bytes:
    """
    Create a nonce including session ID, epoch and message number.
    
    Nonce is 96 bits (12 bytes):
    - 4 bytes: session ID
    - 4 bytes: epoch (truncated to 32 bits)
    - 4 bytes: counter (truncated to 32 bits)
    """
    return struct.pack(">III", sid, epoch & 0xFFFFFFFF, ctr & 0xFFFFFFFF)


def encrypt(mk: bytes, sid: int, epoch: int, ctr: int, ad: bytes, pt: bytes) -> bytes:
    """
    Encrypt plaintext using ChaCha20-Poly1305 (Section 11.2).
    
    Args:
        mk: Message key (32 bytes)
        sid: Session ID
        epoch: Current epoch
        ctr: Message counter
        ad: Associated data
        pt: Plaintext
        
    Returns:
        Ciphertext with authentication tag
        
    Note: The caller is responsible for zeroing the message key after use.
    """
    nonce = make_nonce(sid, epoch, ctr)
    cipher = ChaCha20_Poly1305.new(key=mk, nonce=nonce)
    cipher.update(ad)
    ciphertext, tag = cipher.encrypt_and_digest(pt)
    return ciphertext + tag


def decrypt(mk: bytes, sid: int, epoch: int, ctr: int, ad: bytes, ct: bytes) -> bytes:
    """
    Decrypt ciphertext using ChaCha20-Poly1305 (Section 12).
    
    Args:
        mk: Message key (32 bytes)
        sid: Session ID
        epoch: Current epoch
        ctr: Message counter
        ad: Associated data
        ct: Ciphertext with authentication tag
        
    Returns:
        Decrypted plaintext
        
    Raises:
        DecryptionFailed: If decryption or authentication fails
        
    Note: The caller is responsible for zeroing the message key after use.
    """
    if len(ct) < 16:
        raise DecryptionFailed("Ciphertext too short")
    
    nonce = make_nonce(sid, epoch, ctr)
    ciphertext = ct[:-16]
    tag = ct[-16:]
    
    cipher = ChaCha20_Poly1305.new(key=mk, nonce=nonce)
    cipher.update(ad)
    
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    except ValueError as e:
        raise DecryptionFailed(f"Decryption failed: {e}")

