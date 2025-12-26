//! Cryptographic operations using ChaCha20-Poly1305.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use zeroize::Zeroize;

use crate::error::{Dice52Error, Result};

/// Securely zero a byte slice
pub fn zero_bytes(bytes: &mut [u8]) {
    bytes.zeroize();
}

/// Generates n random bytes
pub fn rand_bytes(n: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

/// Creates a nonce including session ID, epoch and message number
fn make_nonce(sid: u32, epoch: u64, ctr: u64) -> ([u8; 12], Nonce) {
    let mut n = [0u8; 12];
    n[0..4].copy_from_slice(&sid.to_be_bytes());
    n[4..8].copy_from_slice(&(epoch as u32).to_be_bytes());
    n[8..12].copy_from_slice(&(ctr as u32).to_be_bytes());
    let nonce = Nonce::from(n);
    (n, nonce)
}

/// Encrypts plaintext using ChaCha20-Poly1305 (Section 11.2)
///
/// # Arguments
/// * `mk` - Message key (32 bytes)
/// * `sid` - Session ID
/// * `epoch` - Current epoch
/// * `ctr` - Message counter
/// * `ad` - Associated data
/// * `pt` - Plaintext
///
/// # Returns
/// Ciphertext with authentication tag
///
/// Note: The caller is responsible for zeroing the message key after use.
pub fn encrypt(mk: &[u8], sid: u32, epoch: u64, ctr: u64, ad: &[u8], pt: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new_from_slice(mk).expect("Invalid key length");
    let (mut n, nonce) = make_nonce(sid, epoch, ctr);

    let ct = cipher
        .encrypt(&nonce, chacha20poly1305::aead::Payload { msg: pt, aad: ad })
        .expect("Encryption should not fail");

    n.zeroize(); // Zero nonce after use
    ct
}

/// Decrypts ciphertext using ChaCha20-Poly1305 (Section 12)
///
/// # Arguments
/// * `mk` - Message key (32 bytes)
/// * `sid` - Session ID
/// * `epoch` - Current epoch
/// * `ctr` - Message counter
/// * `ad` - Associated data
/// * `ct` - Ciphertext with authentication tag
///
/// # Returns
/// Decrypted plaintext or error
///
/// Note: The caller is responsible for zeroing the message key after use.
pub fn decrypt(mk: &[u8], sid: u32, epoch: u64, ctr: u64, ad: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(mk).expect("Invalid key length");
    let (mut n, nonce) = make_nonce(sid, epoch, ctr);

    let result = cipher
        .decrypt(&nonce, chacha20poly1305::aead::Payload { msg: ct, aad: ad })
        .map_err(|e| Dice52Error::DecryptionFailed(e.to_string()));

    n.zeroize(); // Zero nonce after use
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let mk = rand_bytes(32);
        let sid = 1u32;
        let epoch = 0u64;
        let ctr = 0u64;
        let ad = b"test associated data";
        let pt = b"Hello, quantum world!";

        let ct = encrypt(&mk, sid, epoch, ctr, ad, pt);
        let decrypted = decrypt(&mk, sid, epoch, ctr, ad, &ct).unwrap();

        assert_eq!(decrypted, pt);
    }

    #[test]
    fn test_decrypt_with_wrong_key_fails() {
        let mk = rand_bytes(32);
        let wrong_mk = rand_bytes(32);
        let sid = 1u32;
        let epoch = 0u64;
        let ctr = 0u64;
        let ad = b"test";
        let pt = b"secret";

        let ct = encrypt(&mk, sid, epoch, ctr, ad, pt);
        let result = decrypt(&wrong_mk, sid, epoch, ctr, ad, &ct);

        assert!(result.is_err());
    }
}
