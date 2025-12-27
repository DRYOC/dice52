//! # Dice52
//!
//! Dice52 is a quantum-safe ratchet protocol using hybrid KEM (ML-KEM + X25519) for key
//! encapsulation and ML-DSA (Dilithium) for signatures.
//!
//! ## Features
//!
//! - **Hybrid KEM**: Combines Kyber768 (post-quantum) with X25519 (classical) for defense-in-depth
//! - Post-quantum signatures using Dilithium3
//! - Forward secrecy via ratcheting
//! - Per-message fresh keys
//! - ChaCha20-Poly1305 AEAD encryption
//!
//! The hybrid KEM construction ensures that the shared secret remains secure provided
//! at least one of the component KEMs remains secure.
//!
//! ## Example
//!
//! ```rust,ignore
//! use dice52::{Session, derive_initial_keys, init_chain_keys};
//! use dice52::{initiator_hybrid_encapsulate, responder_hybrid_decapsulate};
//!
//! // See examples in the repository for full usage
//! ```

mod crypto;
mod error;
mod handshake;
mod kdf;
mod session;
mod types;

pub use crypto::{decrypt, encrypt, rand_bytes, zero_bytes};
pub use error::{Dice52Error, Result};
pub use handshake::{
    generate_kem_keypair, generate_signing_keypair, generate_x25519_keypair, initiator_encapsulate,
    initiator_handshake, initiator_hybrid_encapsulate, responder_decapsulate, responder_handshake,
    responder_hybrid_decapsulate, x25519_shared_secret, HybridEncapsulateResult,
};
pub use kdf::{
    ck_to_mk, commit_entropy, derive_enhanced_ko, derive_hybrid_shared_secret, derive_initial_keys,
    derive_ko_commit_key, init_chain_keys, ratchet_rk, verify_commit,
};
pub use session::Session;
pub use types::{
    HandshakeMessage, Header, KoCommitMessage, KoEnhancementState, KoRevealMessage, Message,
    ParanoidConfig, RatchetMessage, CKR_INFO, CKS_INFO, DEFAULT_MAX_MESSAGES_PER_EPOCH,
    HYBRID_SS_INFO, KEY_LEN, KO_COMMIT_KEY_INFO, KO_COMMIT_PREFIX, KO_ENHANCED_INFO, KO_INFO,
    MAX_MESSAGES_PER_EPOCH, MK_INFO, RK_INFO, RK_RATCHET_INFO, SIG_CONTEXT, VERSION,
    X25519_PRIVATE_KEY_SIZE, X25519_PUBLIC_KEY_SIZE,
};
