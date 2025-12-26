//! Handshake protocol using Kyber768 and Dilithium3.

use pqcrypto_dilithium::dilithium3;
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{Ciphertext, SharedSecret};
use pqcrypto_traits::sign::DetachedSignature;

use crate::error::{Dice52Error, Result};
use crate::types::{HandshakeMessage, SIG_CONTEXT};

/// Initiator handshake: encapsulate to peer's KEM public key and sign
///
/// # Arguments
/// * `peer_kem` - Peer's Kyber public key
/// * `id_priv` - Our Dilithium private key for signing
///
/// # Returns
/// Tuple of (handshake_message, shared_secret)
pub fn initiator_handshake(
    peer_kem: &kyber768::PublicKey,
    id_priv: &dilithium3::SecretKey,
) -> Result<(HandshakeMessage, Vec<u8>)> {
    // Encapsulate to peer's public key
    let (ss, ct) = kyber768::encapsulate(peer_kem);

    // Sign: context || ciphertext
    let ct_bytes = ct.as_bytes();
    let mut to_sign = SIG_CONTEXT.to_vec();
    to_sign.extend_from_slice(ct_bytes);

    let sig = dilithium3::detached_sign(&to_sign, id_priv);

    Ok((
        HandshakeMessage {
            kyber_ct: ct_bytes.to_vec(),
            sig: sig.as_bytes().to_vec(),
        },
        ss.as_bytes().to_vec(),
    ))
}

/// Responder handshake: verify signature and decapsulate
///
/// # Arguments
/// * `msg` - Received handshake message
/// * `kem_priv` - Our Kyber private key
/// * `peer_id` - Peer's Dilithium public key for verification
///
/// # Returns
/// Shared secret
pub fn responder_handshake(
    msg: &HandshakeMessage,
    kem_priv: &kyber768::SecretKey,
    peer_id: &dilithium3::PublicKey,
) -> Result<Vec<u8>> {
    // Verify signature
    let mut to_verify = SIG_CONTEXT.to_vec();
    to_verify.extend_from_slice(&msg.kyber_ct);

    let sig = dilithium3::DetachedSignature::from_bytes(&msg.sig)
        .map_err(|_| Dice52Error::InvalidHandshakeSignature)?;

    dilithium3::verify_detached_signature(&sig, &to_verify, peer_id)
        .map_err(|_| Dice52Error::InvalidHandshakeSignature)?;

    // Decapsulate
    let ct = kyber768::Ciphertext::from_bytes(&msg.kyber_ct)
        .map_err(|_| Dice52Error::KemError("invalid ciphertext".into()))?;

    let ss = kyber768::decapsulate(&ct, kem_priv);
    Ok(ss.as_bytes().to_vec())
}

/// Initiator encapsulate: Alice encapsulates to Bob's public key (Section 7)
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

/// Responder decapsulate: Bob decapsulates using his private key (Section 7)
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
    fn test_encapsulate_decapsulate() {
        let (pub_key, priv_key) = generate_kem_keypair();
        let (ss1, ct) = initiator_encapsulate(&pub_key);
        let ss2 = responder_decapsulate(&priv_key, &ct).unwrap();
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn test_handshake() {
        let (_kem_pub_a, _kem_priv_a) = generate_kem_keypair();
        let (kem_pub_b, kem_priv_b) = generate_kem_keypair();
        let (id_pub_a, id_priv_a) = generate_signing_keypair();

        // Alice initiates handshake to Bob
        let (msg, ss_alice) = initiator_handshake(&kem_pub_b, &id_priv_a).unwrap();

        // Bob responds
        let ss_bob = responder_handshake(&msg, &kem_priv_b, &id_pub_a).unwrap();

        assert_eq!(ss_alice, ss_bob);
    }
}
