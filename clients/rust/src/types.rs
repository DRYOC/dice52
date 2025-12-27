//! Constants and types for the Dice52 protocol.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Protocol version
pub const VERSION: u8 = 1;

/// Protocol-specified info strings (Section 8, 9, 10)
pub const RK_INFO: &[u8] = b"Dice52-RK";
pub const KO_INFO: &[u8] = b"Dice52-Ko";
pub const CKS_INFO: &[u8] = b"Dice52-CKs";
pub const CKR_INFO: &[u8] = b"Dice52-CKr";
pub const MK_INFO: &[u8] = b"Dice52-MK";

/// Ratchet info (Section 13)
pub const RK_RATCHET_INFO: &[u8] = b"Dice52-RK-Ratchet";

/// Hybrid KEM info string (Section 3.4)
pub const HYBRID_SS_INFO: &[u8] = b"Dice52-Hybrid-SS";

/// X25519 key sizes
pub const X25519_PUBLIC_KEY_SIZE: usize = 32;
pub const X25519_PRIVATE_KEY_SIZE: usize = 32;

/// Ko enhancement info strings (Section 7.1)
pub const KO_COMMIT_PREFIX: &[u8] = b"Dice52-Ko-Commit";
pub const KO_COMMIT_KEY_INFO: &[u8] = b"Dice52-Ko-CommitKey";
pub const KO_ENHANCED_INFO: &[u8] = b"Dice52-Ko-Enhanced";

/// Signature context (Section 4)
pub const SIG_CONTEXT: &[u8] = b"Dice52-PQ-Signature";

/// Key length in bytes
pub const KEY_LEN: usize = 32;

/// Section 14: Default maximum messages per epoch
pub const DEFAULT_MAX_MESSAGES_PER_EPOCH: u64 = 33;

/// For backwards compatibility
pub const MAX_MESSAGES_PER_EPOCH: u64 = DEFAULT_MAX_MESSAGES_PER_EPOCH;

/// Paranoid mode configuration (Section 7.2)
#[derive(Clone, Debug)]
pub struct ParanoidConfig {
    /// Whether paranoid mode is enabled
    pub enabled: bool,
    /// How often to re-run Ko commit-reveal (in epochs)
    /// Value of 0 means never re-enhance after initial enhancement
    pub ko_reenhance_interval: u64,
    /// Override for max messages per epoch (must be 1-33)
    pub max_messages_per_epoch: u64,
}

impl Default for ParanoidConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ko_reenhance_interval: 0,
            max_messages_per_epoch: DEFAULT_MAX_MESSAGES_PER_EPOCH,
        }
    }
}

impl ParanoidConfig {
    /// Create a new paranoid config with sensible defaults
    pub fn new() -> Self {
        Self {
            enabled: true,
            ko_reenhance_interval: 10,  // Re-enhance Ko every 10 epochs
            max_messages_per_epoch: 16, // Reduced from 33 to 16
        }
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.max_messages_per_epoch < 1 {
            return Err("max_messages_per_epoch must be >= 1");
        }
        if self.max_messages_per_epoch > 33 {
            return Err("max_messages_per_epoch must be <= 33");
        }
        Ok(())
    }
}

/// Handshake message for initial key exchange (Section 6.2)
/// Now includes X25519 public key for hybrid KEM
#[derive(Clone, Debug)]
pub struct HandshakeMessage {
    /// Kyber ciphertext
    pub kyber_ct: Vec<u8>,
    /// X25519 ephemeral public key (32 bytes)
    pub ecdh_pub: Vec<u8>,
    /// Dilithium signature over kyber_ct || ecdh_pub
    pub sig: Vec<u8>,
}

/// Encrypted message with header and body
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Message {
    /// Base64-encoded header (JSON)
    pub header: String,
    /// Base64-encoded ciphertext
    pub body: String,
}

/// Ratchet message for hybrid PQ ratchet key exchange (Section 12)
#[derive(Clone, Debug)]
pub struct RatchetMessage {
    /// New KEM public key (for initiator)
    pub pub_key: Option<Vec<u8>>,
    /// X25519 public key (32 bytes)
    pub ecdh_pub: Option<Vec<u8>>,
    /// Dilithium signature over pub_key || ecdh_pub
    pub sig: Option<Vec<u8>>,
    /// KEM ciphertext (for responder)
    pub ct: Option<Vec<u8>>,
}

/// Header includes all AD fields required by Section 11.1
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Header {
    /// Protocol version
    #[serde(rename = "v")]
    pub version: u8,
    /// Epoch number
    #[serde(rename = "e")]
    pub epoch: u64,
    /// Message number
    #[serde(rename = "n")]
    pub msg_num: u64,
    /// Direction ("send" or "receive")
    #[serde(rename = "d")]
    pub direction: String,
}

/// Ko enhancement commit message (Section 7.1.2)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KoCommitMessage {
    /// Encrypted SHA-256 commitment to local entropy
    pub commit_ct: Vec<u8>,
}

/// Ko enhancement reveal message (Section 7.1.3)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KoRevealMessage {
    /// Encrypted local entropy value
    pub reveal_ct: Vec<u8>,
}

/// State for Ko enhancement protocol
/// Implements Zeroize to securely clear sensitive data when dropped
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KoEnhancementState {
    /// Temporary key for commit/reveal encryption
    pub tk: [u8; 32],
    /// Our local entropy
    pub local_entropy: [u8; 32],
    /// Our commitment
    pub local_commit: [u8; 32],
    /// Peer's commitment (set after receiving)
    #[zeroize(skip)]
    pub peer_commit: Option<[u8; 32]>,
    /// Peer's entropy (set after reveal)
    #[zeroize(skip)]
    pub peer_entropy: Option<[u8; 32]>,
}

impl KoEnhancementState {
    /// Manually zeroize all fields including Options
    pub fn zeroize_all(&mut self) {
        self.tk.zeroize();
        self.local_entropy.zeroize();
        self.local_commit.zeroize();
        if let Some(ref mut c) = self.peer_commit {
            c.zeroize();
        }
        if let Some(ref mut e) = self.peer_entropy {
            e.zeroize();
        }
        self.peer_commit = None;
        self.peer_entropy = None;
    }
}
