//! # Dice52
//!
//! Dice52 is a quantum-safe ratchet protocol using ML-KEM (Kyber) for key encapsulation
//! and ML-DSA (Dilithium) for signatures.
//!
//! ## Features
//!
//! - Post-quantum key exchange using Kyber768
//! - Post-quantum signatures using Dilithium3
//! - Forward secrecy via ratcheting
//! - Per-message fresh keys
//! - ChaCha20-Poly1305 AEAD encryption
//!
//! ## Example
//!
//! ```rust,ignore
//! use dice52::{Session, derive_initial_keys, init_chain_keys};
//! use dice52::{initiator_encapsulate, responder_decapsulate};
//!
//! // See examples in the repository for full usage
//! ```

mod crypto;
mod error;
mod handshake;
mod kdf;
mod session;
mod types;

pub use crypto::{decrypt, encrypt, rand_bytes};
pub use error::{Dice52Error, Result};
pub use handshake::{
    generate_kem_keypair, generate_signing_keypair, initiator_encapsulate, initiator_handshake,
    responder_decapsulate, responder_handshake,
};
pub use kdf::{
    ck_to_mk, commit_entropy, derive_enhanced_ko, derive_initial_keys, derive_ko_commit_key,
    init_chain_keys, ratchet_rk, verify_commit,
};
pub use session::Session;
pub use types::{
    HandshakeMessage, Header, KoCommitMessage, KoEnhancementState, KoRevealMessage, Message,
    RatchetMessage, CKR_INFO, CKS_INFO, KEY_LEN, KO_COMMIT_KEY_INFO, KO_COMMIT_PREFIX,
    KO_ENHANCED_INFO, KO_INFO, MAX_MESSAGES_PER_EPOCH, MK_INFO, RK_INFO, RK_RATCHET_INFO,
    SIG_CONTEXT, VERSION,
};
