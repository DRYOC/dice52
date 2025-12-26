//! Error types for the Dice52 protocol.

use thiserror::Error;

/// Result type alias for Dice52 operations
pub type Result<T> = std::result::Result<T, Dice52Error>;

/// Errors that can occur during Dice52 operations
#[derive(Debug, Error)]
pub enum Dice52Error {
    /// Handshake signature verification failed
    #[error("handshake signature invalid")]
    InvalidHandshakeSignature,

    /// Ratchet signature verification failed
    #[error("ratchet signature invalid")]
    InvalidRatchetSignature,

    /// Message decryption failed
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),

    /// Epoch exhausted, rekey required
    #[error("epoch exhausted: rekey required")]
    EpochExhausted,

    /// Epoch mismatch during receive
    #[error("epoch mismatch")]
    EpochMismatch,

    /// Replay attack detected
    #[error("replay detected: message number too low")]
    ReplayDetected,

    /// Invalid header encoding
    #[error("invalid header encoding: {0}")]
    InvalidHeaderEncoding(String),

    /// Invalid header format
    #[error("invalid header format: {0}")]
    InvalidHeaderFormat(String),

    /// Invalid body encoding
    #[error("invalid body encoding: {0}")]
    InvalidBodyEncoding(String),

    /// KEM operation failed
    #[error("KEM operation failed: {0}")]
    KemError(String),

    /// Key parsing failed
    #[error("key parsing failed: {0}")]
    KeyParseError(String),

    /// Ko enhancement commit verification failed
    #[error("Ko commit verification failed: reveal does not match commitment")]
    KoCommitMismatch,

    /// Ko enhancement protocol error
    #[error("Ko enhancement protocol error: {0}")]
    KoEnhancementError(String),

    /// Configuration error
    #[error("configuration error: {0}")]
    ConfigError(String),
}
