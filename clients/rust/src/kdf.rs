//! Key derivation functions using HKDF-SHA256.

use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use crate::types::{
    CKR_INFO, CKS_INFO, HYBRID_SS_INFO, KEY_LEN, KO_COMMIT_KEY_INFO, KO_COMMIT_PREFIX,
    KO_ENHANCED_INFO, KO_INFO, MK_INFO, RK_INFO, RK_RATCHET_INFO,
};

/// Derives a key using HKDF-SHA256 (Section 3.2)
fn hkdf_expand(secret: &[u8], info: &[u8]) -> [u8; KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(None, secret);
    let mut out = [0u8; KEY_LEN];
    hk.expand(info, &mut out)
        .expect("HKDF expansion should not fail with valid length");
    out
}

/// HKDF expand with salt
fn hkdf_expand_with_salt(secret: &[u8], salt: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(salt), secret);
    let mut out = vec![0u8; out_len];
    hk.expand(info, &mut out)
        .expect("HKDF expansion should not fail");
    out
}

/// Derives hybrid shared secret from Kyber and X25519 shared secrets (Section 3.1)
///
/// SS_hybrid = HKDF(SS_pq || SS_ecdh, "Dice52-Hybrid-SS")
///
/// # Arguments
/// * `ss_pq` - Post-quantum (Kyber) shared secret
/// * `ss_ecdh` - Classical (X25519) shared secret
///
/// # Returns
/// Combined hybrid shared secret
pub fn derive_hybrid_shared_secret(ss_pq: &[u8], ss_ecdh: &[u8]) -> [u8; KEY_LEN] {
    let mut combined = ss_pq.to_vec();
    combined.extend_from_slice(ss_ecdh);
    hkdf_expand(&combined, HYBRID_SS_INFO)
}

/// Derives RK and Ko from shared secret (Section 8)
///
/// # Arguments
/// * `ss` - Shared secret from KEM
///
/// # Returns
/// Tuple of (root_key, ko)
pub fn derive_initial_keys(ss: &[u8]) -> ([u8; KEY_LEN], [u8; KEY_LEN]) {
    let rk = hkdf_expand(ss, RK_INFO);
    let ko = hkdf_expand(&rk, KO_INFO);
    (rk, ko)
}

/// Initializes CKs and CKr from RK and Ko (Section 9)
///
/// # Arguments
/// * `rk` - Root key
/// * `ko` - Ko value
///
/// # Returns
/// Tuple of (chain_key_send, chain_key_receive)
pub fn init_chain_keys(rk: &[u8], ko: &[u8]) -> ([u8; KEY_LEN], [u8; KEY_LEN]) {
    // CKs = HKDF(RK, "Dice52-CKs" || Ko)
    let mut cks_info = CKS_INFO.to_vec();
    cks_info.extend_from_slice(ko);
    let cks = hkdf_expand(rk, &cks_info);

    // CKr = HKDF(RK, "Dice52-CKr" || Ko)
    let mut ckr_info = CKR_INFO.to_vec();
    ckr_info.extend_from_slice(ko);
    let ckr = hkdf_expand(rk, &ckr_info);

    (cks, ckr)
}

/// Performs a PQ ratchet step (Section 13.2)
///
/// # Arguments
/// * `old_rk` - Previous root key
/// * `ss` - New shared secret from ratchet
/// * `ko` - Current Ko value
///
/// # Returns
/// New root key
pub fn ratchet_rk(old_rk: &[u8], ss: &[u8], ko: &[u8]) -> [u8; KEY_LEN] {
    // RK = HKDF(RK || SSᵣ || Ko, "Dice52-RK-Ratchet")
    let mut combined = old_rk.to_vec();
    combined.extend_from_slice(ss);
    combined.extend_from_slice(ko);
    hkdf_expand(&combined, RK_RATCHET_INFO)
}

/// Derives the next chain key and message key (Section 10)
///
/// CK_next || MK = HKDF(CK, "Dice52-MK" || Ko || n)
///
/// # Arguments
/// * `ck` - Current chain key
/// * `ko` - Ko value
/// * `n` - Message number
/// * `dir` - Direction byte
/// * `salt` - Salt (typically RK)
///
/// # Returns
/// Tuple of (next_chain_key, message_key)
pub fn ck_to_mk(
    ck: &[u8],
    ko: &[u8],
    n: u64,
    dir: u8,
    salt: &[u8],
) -> ([u8; KEY_LEN], [u8; KEY_LEN]) {
    let mut info = MK_INFO.to_vec();
    info.extend_from_slice(ko);
    info.push(dir);
    info.extend_from_slice(&n.to_be_bytes());

    let out = hkdf_expand_with_salt(ck, salt, &info, 64);

    let mut next_ck = [0u8; KEY_LEN];
    let mut mk = [0u8; KEY_LEN];
    next_ck.copy_from_slice(&out[..32]);
    mk.copy_from_slice(&out[32..]);

    (next_ck, mk)
}

// ============================================================================
// Ko Enhancement Functions (Section 7.1)
// ============================================================================

/// Derives the temporary key for Ko enhancement commit/reveal encryption
///
/// # Arguments
/// * `ss` - Shared secret from initial handshake
///
/// # Returns
/// Temporary key for encrypting commits and reveals
pub fn derive_ko_commit_key(ss: &[u8]) -> [u8; KEY_LEN] {
    hkdf_expand(ss, KO_COMMIT_KEY_INFO)
}

/// Creates a commitment to entropy (Section 7.1.2)
///
/// # Arguments
/// * `session_id` - Session identifier
/// * `entropy` - Local random entropy (32 bytes)
///
/// # Returns
/// SHA-256 commitment
pub fn commit_entropy(session_id: u32, entropy: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(KO_COMMIT_PREFIX);
    hasher.update(session_id.to_be_bytes());
    hasher.update(entropy);
    hasher.finalize().into()
}

/// Verifies an entropy commitment (Section 7.1.3)
///
/// # Arguments
/// * `session_id` - Session identifier
/// * `entropy` - Revealed entropy
/// * `commit` - Previously received commitment
///
/// # Returns
/// True if commitment is valid
pub fn verify_commit(session_id: u32, entropy: &[u8], commit: &[u8]) -> bool {
    let expected = commit_entropy(session_id, entropy);
    constant_time_eq(&expected, commit)
}

/// Constant-time equality comparison
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Derives enhanced Ko with contributed entropy from both parties (Section 7.1.4)
///
/// # Arguments
/// * `ko_base` - Original Ko derived from handshake
/// * `r_initiator` - Initiator's random contribution
/// * `r_responder` - Responder's random contribution
///
/// # Returns
/// Enhanced Ko with independent entropy
pub fn derive_enhanced_ko(ko_base: &[u8], r_initiator: &[u8], r_responder: &[u8]) -> [u8; KEY_LEN] {
    let mut combined = ko_base.to_vec();
    combined.extend_from_slice(r_initiator);
    combined.extend_from_slice(r_responder);
    hkdf_expand(&combined, KO_ENHANCED_INFO)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_initial_keys() {
        let ss = [0u8; 32];
        let (rk, ko) = derive_initial_keys(&ss);
        assert_eq!(rk.len(), KEY_LEN);
        assert_eq!(ko.len(), KEY_LEN);
        // Keys should be different
        assert_ne!(rk, ko);
    }

    #[test]
    fn test_init_chain_keys() {
        let rk = [1u8; KEY_LEN];
        let ko = [2u8; KEY_LEN];
        let (cks, ckr) = init_chain_keys(&rk, &ko);
        assert_eq!(cks.len(), KEY_LEN);
        assert_eq!(ckr.len(), KEY_LEN);
        // Chain keys should be different
        assert_ne!(cks, ckr);
    }

    #[test]
    fn test_commit_verify() {
        let session_id = 12345u32;
        let entropy = [42u8; 32];
        let commit = commit_entropy(session_id, &entropy);

        // Verification should succeed with correct entropy
        assert!(verify_commit(session_id, &entropy, &commit));

        // Verification should fail with wrong entropy
        let wrong_entropy = [99u8; 32];
        assert!(!verify_commit(session_id, &wrong_entropy, &commit));

        // Verification should fail with wrong session_id
        assert!(!verify_commit(99999, &entropy, &commit));
    }

    #[test]
    fn test_derive_enhanced_ko() {
        let ko_base = [1u8; 32];
        let r_init = [2u8; 32];
        let r_resp = [3u8; 32];

        let enhanced = derive_enhanced_ko(&ko_base, &r_init, &r_resp);
        assert_eq!(enhanced.len(), KEY_LEN);

        // Should be deterministic
        let enhanced2 = derive_enhanced_ko(&ko_base, &r_init, &r_resp);
        assert_eq!(enhanced, enhanced2);

        // Different inputs should produce different outputs
        let enhanced3 = derive_enhanced_ko(&ko_base, &r_resp, &r_init);
        assert_ne!(enhanced, enhanced3);
    }

    #[test]
    fn test_derive_ko_commit_key() {
        let ss = [5u8; 32];
        let tk = derive_ko_commit_key(&ss);
        assert_eq!(tk.len(), KEY_LEN);

        // Should be deterministic
        let tk2 = derive_ko_commit_key(&ss);
        assert_eq!(tk, tk2);
    }
}
