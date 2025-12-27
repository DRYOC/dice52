//! Handshake protocol using hybrid KEM (Kyber768 + X25519) and Dilithium3.

use pqcrypto_dilithium::dilithium3;
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{Ciphertext, SharedSecret};
use pqcrypto_traits::sign::DetachedSignature;
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

use crate::error::{Dice52Error, Result};
use crate::kdf::derive_hybrid_shared_secret;
use crate::types::{HandshakeMessage, SIG_CONTEXT};

/// Result of hybrid encapsulation
pub struct HybridEncapsulateResult {
    /// Combined hybrid shared secret
    pub ss_hybrid: Vec<u8>,
    /// Kyber ciphertext
    pub kyber_ct: Vec<u8>,
    /// Our X25519 public key
    pub ecdh_pub: Vec<u8>,
    /// Our X25519 private key (for session storage)
    pub ecdh_priv: Vec<u8>,
}

/// Generate a new X25519 key pair
pub fn generate_x25519_keypair() -> (Vec<u8>, Vec<u8>) {
    let secret = X25519StaticSecret::random_from_rng(OsRng);
    let public = X25519PublicKey::from(&secret);
    (public.as_bytes().to_vec(), secret.as_bytes().to_vec())
}

/// Compute X25519 shared secret
pub fn x25519_shared_secret(our_priv: &[u8], peer_pub: &[u8]) -> Result<Vec<u8>> {
    if our_priv.len() != 32 || peer_pub.len() != 32 {
        return Err(Dice52Error::KemError("invalid X25519 key length".into()));
    }

    let mut priv_bytes = [0u8; 32];
    let mut pub_bytes = [0u8; 32];
    priv_bytes.copy_from_slice(our_priv);
    pub_bytes.copy_from_slice(peer_pub);

    let secret = X25519StaticSecret::from(priv_bytes);
    let public = X25519PublicKey::from(pub_bytes);
    let shared = secret.diffie_hellman(&public);

    Ok(shared.as_bytes().to_vec())
}

/// Initiator handshake: hybrid encapsulation to peer's public keys and sign (Section 6.2)
///
/// # Arguments
/// * `peer_kem` - Peer's Kyber public key
/// * `peer_ecdh` - Peer's X25519 public key
/// * `id_priv` - Our Dilithium private key for signing
///
/// # Returns
/// Tuple of (handshake_message, hybrid_shared_secret, our_ecdh_private_key)
pub fn initiator_handshake(
    peer_kem: &kyber768::PublicKey,
    peer_ecdh: &[u8],
    id_priv: &dilithium3::SecretKey,
) -> Result<(HandshakeMessage, Vec<u8>, Vec<u8>)> {
    // Generate ephemeral X25519 key pair
    let (ecdh_pub, ecdh_priv) = generate_x25519_keypair();

    // Kyber encapsulation
    let (ss_pq, ct) = kyber768::encapsulate(peer_kem);

    // X25519 key agreement
    let ss_ecdh = x25519_shared_secret(&ecdh_priv, peer_ecdh)?;

    // Derive hybrid shared secret
    let ss_hybrid = derive_hybrid_shared_secret(ss_pq.as_bytes(), &ss_ecdh);

    // Sign: context || ciphertext || ecdh_pub
    let ct_bytes = ct.as_bytes();
    let mut to_sign = SIG_CONTEXT.to_vec();
    to_sign.extend_from_slice(ct_bytes);
    to_sign.extend_from_slice(&ecdh_pub);

    let sig = dilithium3::detached_sign(&to_sign, id_priv);

    Ok((
        HandshakeMessage {
            kyber_ct: ct_bytes.to_vec(),
            ecdh_pub,
            sig: sig.as_bytes().to_vec(),
        },
        ss_hybrid.to_vec(),
        ecdh_priv,
    ))
}

/// Responder handshake: verify signature and hybrid decapsulation (Section 6.3)
///
/// # Arguments
/// * `msg` - Received handshake message
/// * `kem_priv` - Our Kyber private key
/// * `ecdh_priv` - Our X25519 private key
/// * `peer_id` - Peer's Dilithium public key for verification
///
/// # Returns
/// Hybrid shared secret
pub fn responder_handshake(
    msg: &HandshakeMessage,
    kem_priv: &kyber768::SecretKey,
    ecdh_priv: &[u8],
    peer_id: &dilithium3::PublicKey,
) -> Result<Vec<u8>> {
    // Verify signature over context || ciphertext || ecdh_pub
    let mut to_verify = SIG_CONTEXT.to_vec();
    to_verify.extend_from_slice(&msg.kyber_ct);
    to_verify.extend_from_slice(&msg.ecdh_pub);

    let sig = dilithium3::DetachedSignature::from_bytes(&msg.sig)
        .map_err(|_| Dice52Error::InvalidHandshakeSignature)?;

    dilithium3::verify_detached_signature(&sig, &to_verify, peer_id)
        .map_err(|_| Dice52Error::InvalidHandshakeSignature)?;

    // Decapsulate Kyber
    let ct = kyber768::Ciphertext::from_bytes(&msg.kyber_ct)
        .map_err(|_| Dice52Error::KemError("invalid ciphertext".into()))?;

    let ss_pq = kyber768::decapsulate(&ct, kem_priv);

    // X25519 key agreement
    let ss_ecdh = x25519_shared_secret(ecdh_priv, &msg.ecdh_pub)?;

    // Derive hybrid shared secret
    let ss_hybrid = derive_hybrid_shared_secret(ss_pq.as_bytes(), &ss_ecdh);

    Ok(ss_hybrid.to_vec())
}

/// Initiator hybrid encapsulate: Alice encapsulates to Bob's public keys
///
/// # Arguments
/// * `peer_kem` - Peer's Kyber public key
/// * `peer_ecdh` - Peer's X25519 public key
///
/// # Returns
/// HybridEncapsulateResult containing hybrid shared secret, ciphertexts, and keys
pub fn initiator_hybrid_encapsulate(
    peer_kem: &kyber768::PublicKey,
    peer_ecdh: &[u8],
) -> Result<HybridEncapsulateResult> {
    // Generate ephemeral X25519 key pair
    let (ecdh_pub, ecdh_priv) = generate_x25519_keypair();

    // Kyber encapsulation
    let (ss_pq, ct) = kyber768::encapsulate(peer_kem);

    // X25519 key agreement
    let ss_ecdh = x25519_shared_secret(&ecdh_priv, peer_ecdh)?;

    // Derive hybrid shared secret
    let ss_hybrid = derive_hybrid_shared_secret(ss_pq.as_bytes(), &ss_ecdh);

    Ok(HybridEncapsulateResult {
        ss_hybrid: ss_hybrid.to_vec(),
        kyber_ct: ct.as_bytes().to_vec(),
        ecdh_pub,
        ecdh_priv,
    })
}

/// Responder hybrid decapsulate: Bob decapsulates using his private keys
///
/// # Arguments
/// * `kem_priv` - Our Kyber private key
/// * `ecdh_priv` - Our X25519 private key
/// * `kyber_ct` - Received Kyber ciphertext
/// * `peer_ecdh_pub` - Peer's X25519 public key
///
/// # Returns
/// Hybrid shared secret
pub fn responder_hybrid_decapsulate(
    kem_priv: &kyber768::SecretKey,
    ecdh_priv: &[u8],
    kyber_ct: &[u8],
    peer_ecdh_pub: &[u8],
) -> Result<Vec<u8>> {
    // Decapsulate Kyber
    let ct = kyber768::Ciphertext::from_bytes(kyber_ct)
        .map_err(|_| Dice52Error::KemError("invalid ciphertext".into()))?;

    let ss_pq = kyber768::decapsulate(&ct, kem_priv);

    // X25519 key agreement
    let ss_ecdh = x25519_shared_secret(ecdh_priv, peer_ecdh_pub)?;

    // Derive hybrid shared secret
    let ss_hybrid = derive_hybrid_shared_secret(ss_pq.as_bytes(), &ss_ecdh);

    Ok(ss_hybrid.to_vec())
}

// Legacy functions for backwards compatibility (Kyber-only)

/// Initiator encapsulate: Alice encapsulates to Bob's public key (Kyber-only, legacy)
///
/// # Arguments
/// * `peer_pub` - Peer's Kyber public key
///
/// # Returns
/// Tuple of (shared_secret, ciphertext)
pub fn initiator_encapsulate(peer_pub: &kyber768::PublicKey) -> (Vec<u8>, Vec<u8>) {
    let (ss, ct) = kyber768::encapsulate(peer_pub);
    (ss.as_bytes().to_vec(), ct.as_bytes().to_vec())
}

/// Responder decapsulate: Bob decapsulates using his private key (Kyber-only, legacy)
///
/// # Arguments
/// * `our_priv` - Our Kyber private key
/// * `ct` - Received ciphertext
///
/// # Returns
/// Shared secret
pub fn responder_decapsulate(our_priv: &kyber768::SecretKey, ct: &[u8]) -> Result<Vec<u8>> {
    let ct = kyber768::Ciphertext::from_bytes(ct)
        .map_err(|_| Dice52Error::KemError("invalid ciphertext".into()))?;

    let ss = kyber768::decapsulate(&ct, our_priv);
    Ok(ss.as_bytes().to_vec())
}

/// Generate a new Kyber768 key pair
pub fn generate_kem_keypair() -> (kyber768::PublicKey, kyber768::SecretKey) {
    kyber768::keypair()
}

/// Generate a new Dilithium3 key pair
pub fn generate_signing_keypair() -> (dilithium3::PublicKey, dilithium3::SecretKey) {
    dilithium3::keypair()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x25519_key_exchange() {
        let (pub_a, priv_a) = generate_x25519_keypair();
        let (pub_b, priv_b) = generate_x25519_keypair();

        let ss_a = x25519_shared_secret(&priv_a, &pub_b).unwrap();
        let ss_b = x25519_shared_secret(&priv_b, &pub_a).unwrap();

        assert_eq!(ss_a, ss_b);
    }

    #[test]
    fn test_encapsulate_decapsulate() {
        let (pub_key, priv_key) = generate_kem_keypair();
        let (ss1, ct) = initiator_encapsulate(&pub_key);
        let ss2 = responder_decapsulate(&priv_key, &ct).unwrap();
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn test_hybrid_encapsulate_decapsulate() {
        let (kem_pub, kem_priv) = generate_kem_keypair();
        let (ecdh_pub, ecdh_priv) = generate_x25519_keypair();

        let result = initiator_hybrid_encapsulate(&kem_pub, &ecdh_pub).unwrap();

        let ss2 =
            responder_hybrid_decapsulate(&kem_priv, &ecdh_priv, &result.kyber_ct, &result.ecdh_pub)
                .unwrap();

        assert_eq!(result.ss_hybrid, ss2);
    }

    #[test]
    fn test_hybrid_handshake() {
        let (_kem_pub_a, _kem_priv_a) = generate_kem_keypair();
        let (kem_pub_b, kem_priv_b) = generate_kem_keypair();
        let (_ecdh_pub_a, _ecdh_priv_a) = generate_x25519_keypair();
        let (ecdh_pub_b, ecdh_priv_b) = generate_x25519_keypair();
        let (id_pub_a, id_priv_a) = generate_signing_keypair();

        // Alice initiates hybrid handshake to Bob
        let (msg, ss_alice, _ecdh_priv) =
            initiator_handshake(&kem_pub_b, &ecdh_pub_b, &id_priv_a).unwrap();

        // Bob responds using hybrid decapsulation
        let ss_bob = responder_handshake(&msg, &kem_priv_b, &ecdh_priv_b, &id_pub_a).unwrap();

        assert_eq!(ss_alice, ss_bob);
    }
}
