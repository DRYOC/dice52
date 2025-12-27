//! Session management for Dice52 protocol.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use parking_lot::Mutex;
use pqcrypto_dilithium::dilithium3;
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{Ciphertext, PublicKey as KemPublicKey, SharedSecret};
use pqcrypto_traits::sign::DetachedSignature;

use crate::crypto::{decrypt, encrypt, rand_bytes, zero_bytes};
use crate::error::{Dice52Error, Result};
use crate::handshake::{generate_kem_keypair, generate_x25519_keypair, x25519_shared_secret};
use crate::kdf::{
    ck_to_mk, commit_entropy, derive_enhanced_ko, derive_hybrid_shared_secret,
    derive_ko_commit_key, init_chain_keys, verify_commit,
};
use crate::types::{
    Header, KoCommitMessage, KoEnhancementState, KoRevealMessage, Message, ParanoidConfig,
    RatchetMessage, DEFAULT_MAX_MESSAGES_PER_EPOCH, KO_INFO, RK_RATCHET_INFO, SIG_CONTEXT, VERSION,
};

/// Session state for a Dice52 PQ ratchet session
pub struct Session {
    inner: Mutex<SessionInner>,
}

struct SessionInner {
    /// Root key
    rk: [u8; 32],
    /// Chain key for sending
    cks: [u8; 32],
    /// Chain key for receiving
    ckr: [u8; 32],
    /// Ko value for ordering
    ko: [u8; 32],

    /// Send message counter
    ns: u64,
    /// Receive message counter
    nr: u64,
    /// Epoch counter
    epoch: u64,

    /// Our KEM private key (Kyber)
    kem_priv: kyber768::SecretKey,
    /// Our KEM public key (Kyber)
    kem_pub: kyber768::PublicKey,

    /// Our X25519 private key for hybrid KEM
    ecdh_priv: Vec<u8>,
    /// Our X25519 public key for hybrid KEM
    ecdh_pub: Vec<u8>,

    /// Our identity private key (Dilithium)
    id_priv: dilithium3::SecretKey,
    /// Our identity public key (Dilithium) - kept for potential future use
    #[allow(dead_code)]
    id_pub: dilithium3::PublicKey,
    /// Peer's identity public key
    peer_id: dilithium3::PublicKey,

    /// Session ID
    session_id: u32,

    /// Ko enhancement state (present during enhancement phase)
    ko_enhancement: Option<KoEnhancementState>,

    /// Whether Ko has been enhanced
    ko_enhanced: bool,

    /// Whether this session is the initiator
    is_initiator: bool,

    /// Paranoid mode configuration (Section 7.2)
    paranoid_config: ParanoidConfig,

    /// Epoch when Ko was last enhanced
    last_ko_enhanced_epoch: u64,

    /// Flag indicating Ko re-enhancement is needed
    pending_ko_reenhance: bool,

    /// Stored shared secret for Ko re-enhancement (only in paranoid mode)
    last_shared_secret: Option<Vec<u8>>,
}

impl Session {
    /// Create a new session with the given parameters
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: u32,
        rk: [u8; 32],
        ko: [u8; 32],
        cks: [u8; 32],
        ckr: [u8; 32],
        kem_pub: kyber768::PublicKey,
        kem_priv: kyber768::SecretKey,
        id_pub: dilithium3::PublicKey,
        id_priv: dilithium3::SecretKey,
        peer_id: dilithium3::PublicKey,
    ) -> Self {
        Self::new_with_role(
            session_id, rk, ko, cks, ckr, kem_pub, kem_priv, id_pub, id_priv, peer_id, true,
        )
    }

    /// Create a new session with explicit initiator/responder role
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_role(
        session_id: u32,
        rk: [u8; 32],
        ko: [u8; 32],
        cks: [u8; 32],
        ckr: [u8; 32],
        kem_pub: kyber768::PublicKey,
        kem_priv: kyber768::SecretKey,
        id_pub: dilithium3::PublicKey,
        id_priv: dilithium3::SecretKey,
        peer_id: dilithium3::PublicKey,
        is_initiator: bool,
    ) -> Self {
        // Generate initial X25519 keypair
        let (ecdh_pub, ecdh_priv) = generate_x25519_keypair();

        Self {
            inner: Mutex::new(SessionInner {
                rk,
                cks,
                ckr,
                ko,
                ns: 0,
                nr: 0,
                epoch: 0,
                kem_priv,
                kem_pub,
                ecdh_priv,
                ecdh_pub,
                id_priv,
                id_pub,
                peer_id,
                session_id,
                ko_enhancement: None,
                ko_enhanced: false,
                is_initiator,
                paranoid_config: ParanoidConfig::default(),
                last_ko_enhanced_epoch: 0,
                pending_ko_reenhance: false,
                last_shared_secret: None,
            }),
        }
    }

    /// Create a new session with explicit X25519 keys for hybrid KEM
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_ecdh(
        session_id: u32,
        rk: [u8; 32],
        ko: [u8; 32],
        cks: [u8; 32],
        ckr: [u8; 32],
        kem_pub: kyber768::PublicKey,
        kem_priv: kyber768::SecretKey,
        ecdh_pub: Vec<u8>,
        ecdh_priv: Vec<u8>,
        _peer_ecdh_pub: Vec<u8>, // Stored for future ratchets
        id_pub: dilithium3::PublicKey,
        id_priv: dilithium3::SecretKey,
        peer_id: dilithium3::PublicKey,
        is_initiator: bool,
    ) -> Self {
        Self {
            inner: Mutex::new(SessionInner {
                rk,
                cks,
                ckr,
                ko,
                ns: 0,
                nr: 0,
                epoch: 0,
                kem_priv,
                kem_pub,
                ecdh_priv,
                ecdh_pub,
                id_priv,
                id_pub,
                peer_id,
                session_id,
                ko_enhancement: None,
                ko_enhanced: false,
                is_initiator,
                paranoid_config: ParanoidConfig::default(),
                last_ko_enhanced_epoch: 0,
                pending_ko_reenhance: false,
                last_shared_secret: None,
            }),
        }
    }

    /// Enable paranoid mode with the given configuration
    pub fn set_paranoid_mode(&self, config: ParanoidConfig) -> Result<()> {
        config
            .validate()
            .map_err(|e| Dice52Error::ConfigError(e.to_string()))?;
        self.inner.lock().paranoid_config = config;
        Ok(())
    }

    /// Get the current paranoid mode configuration
    pub fn get_paranoid_config(&self) -> ParanoidConfig {
        self.inner.lock().paranoid_config.clone()
    }

    /// Check if paranoid mode is enabled
    pub fn is_paranoid_mode(&self) -> bool {
        self.inner.lock().paranoid_config.enabled
    }

    /// Check if Ko re-enhancement is pending
    pub fn needs_ko_reenhancement(&self) -> bool {
        self.inner.lock().pending_ko_reenhance
    }

    /// Get the effective max messages per epoch
    fn get_max_messages_per_epoch(inner: &SessionInner) -> u64 {
        if inner.paranoid_config.enabled && inner.paranoid_config.max_messages_per_epoch > 0 {
            inner.paranoid_config.max_messages_per_epoch
        } else {
            DEFAULT_MAX_MESSAGES_PER_EPOCH
        }
    }

    /// Send encrypts and sends a message (Section 11)
    pub fn send(&self, pt: &[u8]) -> Result<Message> {
        let mut inner = self.inner.lock();

        // Section 14: Enforce epoch limit (configurable in paranoid mode)
        let max_messages = Self::get_max_messages_per_epoch(&inner);
        if inner.ns >= max_messages {
            return Err(Dice52Error::EpochExhausted);
        }

        let (next_ck, mut mk) = ck_to_mk(&inner.cks, &inner.ko, inner.ns, 0, &inner.rk);
        inner.cks = next_ck;

        // Section 11.1: AD must include version, epoch, message number, direction
        let header = Header {
            version: VERSION,
            epoch: inner.epoch,
            msg_num: inner.ns,
            direction: "send".to_string(),
        };
        let ad = serde_json::to_vec(&header).expect("Header serialization should not fail");

        let ct = encrypt(&mk, inner.session_id, inner.epoch, inner.ns, &ad, pt);
        zero_bytes(&mut mk); // Zero message key after use
        inner.ns += 1;

        Ok(Message {
            header: BASE64.encode(&ad),
            body: BASE64.encode(&ct),
        })
    }

    /// Receive decrypts a received message (Section 12)
    pub fn receive(&self, msg: &Message) -> Result<Vec<u8>> {
        let mut inner = self.inner.lock();

        let ad = BASE64
            .decode(&msg.header)
            .map_err(|e| Dice52Error::InvalidHeaderEncoding(e.to_string()))?;

        let header: Header = serde_json::from_slice(&ad)
            .map_err(|e| Dice52Error::InvalidHeaderFormat(e.to_string()))?;

        // Section 16: Message numbers must be monotonically increasing
        if header.msg_num < inner.nr {
            return Err(Dice52Error::ReplayDetected);
        }

        let ct = BASE64
            .decode(&msg.body)
            .map_err(|e| Dice52Error::InvalidBodyEncoding(e.to_string()))?;

        // Enforce epoch match on receive
        if header.epoch != inner.epoch {
            return Err(Dice52Error::EpochMismatch);
        }

        // Derive MK using message number from header (use dir=0 to match sender)
        let (next_ck, mut mk) = ck_to_mk(&inner.ckr, &inner.ko, header.msg_num, 0, &inner.rk);
        inner.ckr = next_ck;

        // Reconstruct AD with send direction for decryption (match sender's AD)
        let recv_header = Header {
            version: header.version,
            epoch: header.epoch,
            msg_num: header.msg_num,
            direction: "send".to_string(),
        };
        let recv_ad =
            serde_json::to_vec(&recv_header).expect("Header serialization should not fail");

        let pt = decrypt(
            &mk,
            inner.session_id,
            header.epoch,
            header.msg_num,
            &recv_ad,
            &ct,
        );
        zero_bytes(&mut mk); // Zero message key after use

        inner.nr = header.msg_num + 1;
        pt
    }

    /// Initiate a hybrid PQ ratchet with Dilithium signature (Section 12.2)
    pub fn initiate_ratchet(&self) -> Result<RatchetMessage> {
        let mut inner = self.inner.lock();

        // Generate new Kyber key pair
        let (pub_key, priv_key) = generate_kem_keypair();
        inner.kem_priv = priv_key;
        inner.kem_pub = pub_key;

        // Generate new X25519 key pair
        let (ecdh_pub, ecdh_priv) = generate_x25519_keypair();
        inner.ecdh_priv = ecdh_priv;
        inner.ecdh_pub = ecdh_pub.clone();

        // Sign both public keys: SigContext || KEMPub || ECDHPub
        let pub_bytes = inner.kem_pub.as_bytes();
        let mut to_sign = SIG_CONTEXT.to_vec();
        to_sign.extend_from_slice(pub_bytes);
        to_sign.extend_from_slice(&ecdh_pub);

        let sig = dilithium3::detached_sign(&to_sign, &inner.id_priv);

        Ok(RatchetMessage {
            pub_key: Some(pub_bytes.to_vec()),
            ecdh_pub: Some(ecdh_pub),
            sig: Some(sig.as_bytes().to_vec()),
            ct: None,
        })
    }

    /// Respond to initiator's hybrid ratchet message (Section 12.3)
    pub fn respond_ratchet(&self, msg: &RatchetMessage) -> Result<RatchetMessage> {
        let mut inner = self.inner.lock();

        let pub_key_bytes = msg.pub_key.as_ref().ok_or(Dice52Error::KemError(
            "missing public key in ratchet message".into(),
        ))?;
        let peer_ecdh_pub = msg.ecdh_pub.as_ref().ok_or(Dice52Error::KemError(
            "missing ECDH public key in ratchet message".into(),
        ))?;
        let sig_bytes = msg
            .sig
            .as_ref()
            .ok_or(Dice52Error::InvalidRatchetSignature)?;

        // Verify signature over SigContext || KEMPub || ECDHPub
        let mut to_verify = SIG_CONTEXT.to_vec();
        to_verify.extend_from_slice(pub_key_bytes);
        to_verify.extend_from_slice(peer_ecdh_pub);

        let sig = dilithium3::DetachedSignature::from_bytes(sig_bytes)
            .map_err(|_| Dice52Error::InvalidRatchetSignature)?;

        dilithium3::verify_detached_signature(&sig, &to_verify, &inner.peer_id)
            .map_err(|_| Dice52Error::InvalidRatchetSignature)?;

        // Parse peer's new Kyber public key
        let peer_pub = kyber768::PublicKey::from_bytes(pub_key_bytes)
            .map_err(|_| Dice52Error::KeyParseError("invalid KEM public key".into()))?;

        // Generate ephemeral X25519 key pair for response
        let (ecdh_pub, ecdh_priv) = generate_x25519_keypair();

        // Kyber encapsulation
        let (ss_pq, ct) = kyber768::encapsulate(&peer_pub);

        // X25519 key agreement
        let ss_ecdh = x25519_shared_secret(&ecdh_priv, peer_ecdh_pub)?;

        // Derive hybrid shared secret
        let ss_hybrid = derive_hybrid_shared_secret(ss_pq.as_bytes(), &ss_ecdh);

        // Apply ratchet with hybrid shared secret (responder)
        Self::apply_ratchet_inner(&mut inner, &ss_hybrid, false);

        Ok(RatchetMessage {
            pub_key: None,
            ecdh_pub: Some(ecdh_pub),
            sig: None,
            ct: Some(ct.as_bytes().to_vec()),
        })
    }

    /// Finalize the hybrid ratchet on the initiator side (Section 12.4)
    pub fn finalize_ratchet(&self, msg: &RatchetMessage) -> Result<()> {
        let mut inner = self.inner.lock();

        let ct_bytes = msg.ct.as_ref().ok_or(Dice52Error::KemError(
            "missing ciphertext in ratchet message".into(),
        ))?;
        let peer_ecdh_pub = msg.ecdh_pub.as_ref().ok_or(Dice52Error::KemError(
            "missing ECDH public key in ratchet response".into(),
        ))?;

        // Decapsulate Kyber ciphertext
        let ct = kyber768::Ciphertext::from_bytes(ct_bytes)
            .map_err(|_| Dice52Error::KemError("invalid ciphertext".into()))?;

        let ss_pq = kyber768::decapsulate(&ct, &inner.kem_priv);

        // X25519 key agreement with responder's ephemeral public key
        let ss_ecdh = x25519_shared_secret(&inner.ecdh_priv, peer_ecdh_pub)?;

        // Derive hybrid shared secret
        let ss_hybrid = derive_hybrid_shared_secret(ss_pq.as_bytes(), &ss_ecdh);

        Self::apply_ratchet_inner(&mut inner, &ss_hybrid, true); // Initiator
        Ok(())
    }

    /// Internal ratchet application
    fn apply_ratchet_inner(inner: &mut SessionInner, ss: &[u8], as_initiator: bool) {
        use hkdf::Hkdf;
        use sha2::Sha256;

        // RK = HKDF(RK || SS || Ko, "Dice52-RK-Ratchet")
        let mut combined = inner.rk.to_vec();
        combined.extend_from_slice(ss);
        combined.extend_from_slice(&inner.ko);

        let hk = Hkdf::<Sha256>::new(None, &combined);
        hk.expand(RK_RATCHET_INFO, &mut inner.rk)
            .expect("HKDF expansion should not fail");

        // Ko = HKDF(RK, "Dice52-Ko")
        let hk = Hkdf::<Sha256>::new(None, &inner.rk);
        hk.expand(KO_INFO, &mut inner.ko)
            .expect("HKDF expansion should not fail");

        // Reinitialize chain keys
        let (cks, ckr) = init_chain_keys(&inner.rk, &inner.ko);
        if as_initiator {
            // Ratchet initiator: CKs sends, CKr receives
            inner.cks = cks;
            inner.ckr = ckr;
        } else {
            // Ratchet responder: swap keys (responder's send = initiator's receive)
            inner.cks = ckr;
            inner.ckr = cks;
        }
        inner.ns = 0;
        inner.nr = 0;
        inner.epoch += 1;

        // Paranoid mode: Check if Ko re-enhancement is needed (Section 7.2)
        if inner.paranoid_config.enabled && inner.paranoid_config.ko_reenhance_interval > 0 {
            let epochs_since_last_enhance = inner.epoch - inner.last_ko_enhanced_epoch;
            if epochs_since_last_enhance >= inner.paranoid_config.ko_reenhance_interval {
                inner.pending_ko_reenhance = true;
                // Store shared secret for re-enhancement
                inner.last_shared_secret = Some(ss.to_vec());
            }
        }
    }

    /// Get current epoch
    pub fn epoch(&self) -> u64 {
        self.inner.lock().epoch
    }

    /// Get session ID
    pub fn session_id(&self) -> u32 {
        self.inner.lock().session_id
    }

    /// Check if Ko has been enhanced
    pub fn is_ko_enhanced(&self) -> bool {
        self.inner.lock().ko_enhanced
    }

    // =========================================================================
    // Ko Enhancement Protocol (Section 7.1)
    // =========================================================================

    /// Start Ko enhancement: generate local entropy and create commit message
    ///
    /// # Arguments
    /// * `ss` - Original shared secret from handshake (for deriving TK)
    ///
    /// # Returns
    /// Commit message to send to peer
    pub fn ko_start_enhancement(&self, ss: &[u8]) -> Result<KoCommitMessage> {
        use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};

        let mut inner = self.inner.lock();

        if inner.ko_enhanced {
            return Err(Dice52Error::KoEnhancementError(
                "Ko already enhanced".into(),
            ));
        }

        // Generate local entropy
        let entropy_vec = rand_bytes(32);
        let mut local_entropy = [0u8; 32];
        local_entropy.copy_from_slice(&entropy_vec);

        // Derive temporary key
        let tk = derive_ko_commit_key(ss);

        // Create commitment
        let local_commit = commit_entropy(inner.session_id, &local_entropy);

        // Encrypt commitment with TK (nonce = 0 for commit)
        let cipher = ChaCha20Poly1305::new_from_slice(&tk).expect("Invalid key length");
        let nonce = Nonce::from([0u8; 12]);
        let commit_ct = cipher
            .encrypt(
                &nonce,
                chacha20poly1305::aead::Payload {
                    msg: &local_commit,
                    aad: b"ko-commit",
                },
            )
            .map_err(|e| Dice52Error::KoEnhancementError(format!("encryption failed: {}", e)))?;

        // Store state
        inner.ko_enhancement = Some(KoEnhancementState {
            tk,
            local_entropy,
            local_commit,
            peer_commit: None,
            peer_entropy: None,
        });

        Ok(KoCommitMessage { commit_ct })
    }

    /// Process received commit and create reveal message
    ///
    /// # Arguments
    /// * `peer_commit_msg` - Commit message received from peer
    ///
    /// # Returns
    /// Reveal message to send to peer
    pub fn ko_process_commit(&self, peer_commit_msg: &KoCommitMessage) -> Result<KoRevealMessage> {
        use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};

        let mut inner = self.inner.lock();

        let state = inner
            .ko_enhancement
            .as_mut()
            .ok_or_else(|| Dice52Error::KoEnhancementError("enhancement not started".into()))?;

        // Decrypt peer's commit
        let cipher = ChaCha20Poly1305::new_from_slice(&state.tk).expect("Invalid key length");
        let nonce = Nonce::from([0u8; 12]);
        let peer_commit_bytes = cipher
            .decrypt(
                &nonce,
                chacha20poly1305::aead::Payload {
                    msg: &peer_commit_msg.commit_ct,
                    aad: b"ko-commit",
                },
            )
            .map_err(|e| {
                Dice52Error::KoEnhancementError(format!("commit decryption failed: {}", e))
            })?;

        let mut peer_commit = [0u8; 32];
        if peer_commit_bytes.len() != 32 {
            return Err(Dice52Error::KoEnhancementError(
                "invalid commit length".into(),
            ));
        }
        peer_commit.copy_from_slice(&peer_commit_bytes);
        state.peer_commit = Some(peer_commit);

        // Create reveal (encrypt our entropy with nonce = 1)
        let reveal_nonce = Nonce::from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let reveal_ct = cipher
            .encrypt(
                &reveal_nonce,
                chacha20poly1305::aead::Payload {
                    msg: &state.local_entropy,
                    aad: b"ko-reveal",
                },
            )
            .map_err(|e| {
                Dice52Error::KoEnhancementError(format!("reveal encryption failed: {}", e))
            })?;

        Ok(KoRevealMessage { reveal_ct })
    }

    /// Finalize Ko enhancement with peer's reveal
    ///
    /// # Arguments
    /// * `peer_reveal_msg` - Reveal message received from peer
    pub fn ko_finalize(&self, peer_reveal_msg: &KoRevealMessage) -> Result<()> {
        use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};

        let mut inner = self.inner.lock();

        let mut state = inner
            .ko_enhancement
            .take()
            .ok_or_else(|| Dice52Error::KoEnhancementError("enhancement not started".into()))?;

        let peer_commit = state
            .peer_commit
            .ok_or_else(|| Dice52Error::KoEnhancementError("peer commit not received".into()))?;

        // Decrypt peer's reveal
        let cipher = ChaCha20Poly1305::new_from_slice(&state.tk).expect("Invalid key length");
        let reveal_nonce = Nonce::from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let peer_entropy_bytes = cipher
            .decrypt(
                &reveal_nonce,
                chacha20poly1305::aead::Payload {
                    msg: &peer_reveal_msg.reveal_ct,
                    aad: b"ko-reveal",
                },
            )
            .map_err(|e| {
                Dice52Error::KoEnhancementError(format!("reveal decryption failed: {}", e))
            })?;

        if peer_entropy_bytes.len() != 32 {
            return Err(Dice52Error::KoEnhancementError(
                "invalid reveal length".into(),
            ));
        }

        // Verify commit
        if !verify_commit(inner.session_id, &peer_entropy_bytes, &peer_commit) {
            return Err(Dice52Error::KoCommitMismatch);
        }

        // Determine initiator/responder entropy order
        let (r_initiator, r_responder) = if inner.is_initiator {
            (&state.local_entropy[..], &peer_entropy_bytes[..])
        } else {
            (&peer_entropy_bytes[..], &state.local_entropy[..])
        };

        // Derive enhanced Ko
        inner.ko = derive_enhanced_ko(&inner.ko, r_initiator, r_responder);

        // Zero all sensitive state data before dropping
        state.zeroize_all();

        // Note: We do NOT reinitialize chain keys here.
        // Ko is used in message key derivation (ck_to_mk), so updating Ko
        // is sufficient. Chain keys will continue to evolve naturally.
        // Reinitializing would break the asymmetric chain key assignment
        // between initiator and responder.

        inner.ko_enhanced = true;

        // Track when Ko was last enhanced (for paranoid mode)
        inner.last_ko_enhanced_epoch = inner.epoch;
        inner.pending_ko_reenhance = false;

        Ok(())
    }

    // =========================================================================
    // Paranoid Mode Ko Re-enhancement (Section 7.2)
    // =========================================================================

    /// Start Ko re-enhancement during paranoid mode
    /// This should be called after a ratchet when needs_ko_reenhancement() returns true
    pub fn ko_start_reenhancement(&self) -> Result<KoCommitMessage> {
        use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};

        let mut inner = self.inner.lock();

        if !inner.paranoid_config.enabled {
            return Err(Dice52Error::KoEnhancementError(
                "paranoid mode not enabled".into(),
            ));
        }

        if !inner.pending_ko_reenhance {
            return Err(Dice52Error::KoEnhancementError(
                "Ko re-enhancement not needed".into(),
            ));
        }

        let ss = inner.last_shared_secret.as_ref().ok_or_else(|| {
            Dice52Error::KoEnhancementError("no shared secret available for re-enhancement".into())
        })?;

        // Generate local entropy
        let entropy_vec = rand_bytes(32);
        let mut local_entropy = [0u8; 32];
        local_entropy.copy_from_slice(&entropy_vec);

        // Derive temporary key from the ratchet shared secret
        let tk = derive_ko_commit_key(ss);

        // Create commitment
        let local_commit = commit_entropy(inner.session_id, &local_entropy);

        // Encrypt commitment with TK (nonce = 0 for commit)
        let cipher = ChaCha20Poly1305::new_from_slice(&tk).expect("Invalid key length");
        let nonce = Nonce::from([0u8; 12]);
        let commit_ct = cipher
            .encrypt(
                &nonce,
                chacha20poly1305::aead::Payload {
                    msg: &local_commit,
                    aad: b"ko-reenhance-commit",
                },
            )
            .map_err(|e| Dice52Error::KoEnhancementError(format!("encryption failed: {}", e)))?;

        // Store state
        inner.ko_enhancement = Some(KoEnhancementState {
            tk,
            local_entropy,
            local_commit,
            peer_commit: None,
            peer_entropy: None,
        });

        Ok(KoCommitMessage { commit_ct })
    }

    /// Process received re-enhancement commit
    pub fn ko_process_reenhance_commit(
        &self,
        peer_commit_msg: &KoCommitMessage,
    ) -> Result<KoRevealMessage> {
        use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};

        let mut inner = self.inner.lock();

        let state = inner
            .ko_enhancement
            .as_mut()
            .ok_or_else(|| Dice52Error::KoEnhancementError("re-enhancement not started".into()))?;

        // Decrypt peer's commit
        let cipher = ChaCha20Poly1305::new_from_slice(&state.tk).expect("Invalid key length");
        let nonce = Nonce::from([0u8; 12]);
        let peer_commit_bytes = cipher
            .decrypt(
                &nonce,
                chacha20poly1305::aead::Payload {
                    msg: &peer_commit_msg.commit_ct,
                    aad: b"ko-reenhance-commit",
                },
            )
            .map_err(|e| {
                Dice52Error::KoEnhancementError(format!("commit decryption failed: {}", e))
            })?;

        let mut peer_commit = [0u8; 32];
        if peer_commit_bytes.len() != 32 {
            return Err(Dice52Error::KoEnhancementError(
                "invalid commit length".into(),
            ));
        }
        peer_commit.copy_from_slice(&peer_commit_bytes);
        state.peer_commit = Some(peer_commit);

        // Create reveal (encrypt our entropy with nonce = 1)
        let reveal_nonce = Nonce::from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let reveal_ct = cipher
            .encrypt(
                &reveal_nonce,
                chacha20poly1305::aead::Payload {
                    msg: &state.local_entropy,
                    aad: b"ko-reenhance-reveal",
                },
            )
            .map_err(|e| {
                Dice52Error::KoEnhancementError(format!("reveal encryption failed: {}", e))
            })?;

        Ok(KoRevealMessage { reveal_ct })
    }

    /// Finalize Ko re-enhancement
    pub fn ko_finalize_reenhancement(&self, peer_reveal_msg: &KoRevealMessage) -> Result<()> {
        use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};

        let mut inner = self.inner.lock();

        let mut state = inner
            .ko_enhancement
            .take()
            .ok_or_else(|| Dice52Error::KoEnhancementError("re-enhancement not started".into()))?;

        let peer_commit = state
            .peer_commit
            .ok_or_else(|| Dice52Error::KoEnhancementError("peer commit not received".into()))?;

        // Decrypt peer's reveal
        let cipher = ChaCha20Poly1305::new_from_slice(&state.tk).expect("Invalid key length");
        let reveal_nonce = Nonce::from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let peer_entropy_bytes = cipher
            .decrypt(
                &reveal_nonce,
                chacha20poly1305::aead::Payload {
                    msg: &peer_reveal_msg.reveal_ct,
                    aad: b"ko-reenhance-reveal",
                },
            )
            .map_err(|e| {
                Dice52Error::KoEnhancementError(format!("reveal decryption failed: {}", e))
            })?;

        if peer_entropy_bytes.len() != 32 {
            return Err(Dice52Error::KoEnhancementError(
                "invalid reveal length".into(),
            ));
        }

        // Verify commit
        if !verify_commit(inner.session_id, &peer_entropy_bytes, &peer_commit) {
            return Err(Dice52Error::KoCommitMismatch);
        }

        // Determine initiator/responder entropy order
        let (r_initiator, r_responder) = if inner.is_initiator {
            (&state.local_entropy[..], &peer_entropy_bytes[..])
        } else {
            (&peer_entropy_bytes[..], &state.local_entropy[..])
        };

        // Derive re-enhanced Ko
        inner.ko = derive_enhanced_ko(&inner.ko, r_initiator, r_responder);

        // Zero all sensitive state data
        state.zeroize_all();
        if let Some(ref mut ss) = inner.last_shared_secret {
            zero_bytes(ss);
        }

        // Clear state
        inner.last_ko_enhanced_epoch = inner.epoch;
        inner.pending_ko_reenhance = false;
        inner.last_shared_secret = None;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::{
        generate_signing_keypair, initiator_encapsulate, responder_decapsulate,
    };
    use crate::kdf::derive_initial_keys;

    fn create_test_sessions() -> (Session, Session, Vec<u8>) {
        // Generate KEM key pairs
        let (kem_pub_a, kem_priv_a) = generate_kem_keypair();
        let (kem_pub_b, kem_priv_b) = generate_kem_keypair();

        // Generate identity key pairs
        let (id_pub_a, id_priv_a) = generate_signing_keypair();
        let (id_pub_b, id_priv_b) = generate_signing_keypair();

        // Alice encapsulates to Bob's public key
        let (ss, ct) = initiator_encapsulate(&kem_pub_b);

        // Bob decapsulates
        let ss_bob = responder_decapsulate(&kem_priv_b, &ct).unwrap();

        assert_eq!(ss, ss_bob);

        // Derive initial keys
        let (rk_alice, ko_alice) = derive_initial_keys(&ss);
        let (rk_bob, ko_bob) = derive_initial_keys(&ss_bob);

        // Initialize chain keys
        let (cks_alice, ckr_alice) = init_chain_keys(&rk_alice, &ko_alice);
        let (cks_bob, ckr_bob) = init_chain_keys(&rk_bob, &ko_bob);

        let alice = Session::new_with_role(
            1,
            rk_alice,
            ko_alice,
            cks_alice,
            ckr_alice,
            kem_pub_a,
            kem_priv_a,
            id_pub_a.clone(),
            id_priv_a,
            id_pub_b.clone(),
            true, // Alice is initiator
        );

        // Bob's send = Alice's receive, Bob's receive = Alice's send
        let bob = Session::new_with_role(
            1, rk_bob, ko_bob, ckr_bob, // Bob's send = Alice's receive
            cks_bob, // Bob's receive = Alice's send
            kem_pub_b, kem_priv_b, id_pub_b, id_priv_b, id_pub_a, false, // Bob is responder
        );

        (alice, bob, ss)
    }

    #[test]
    fn test_send_receive() {
        let (alice, bob, _ss) = create_test_sessions();

        let plaintext = b"Quantum-safe hello!";
        let msg = alice.send(plaintext).unwrap();
        let decrypted = bob.receive(&msg).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_multiple_messages() {
        let (alice, bob, _ss) = create_test_sessions();

        for i in 0..5 {
            let plaintext = format!("Message {}", i);
            let msg = alice.send(plaintext.as_bytes()).unwrap();
            let decrypted = bob.receive(&msg).unwrap();
            assert_eq!(decrypted, plaintext.as_bytes());
        }
    }

    #[test]
    fn test_ko_enhancement() {
        let (alice, bob, ss) = create_test_sessions();

        // Both sessions should start without Ko enhancement
        assert!(!alice.is_ko_enhanced());
        assert!(!bob.is_ko_enhanced());

        // Step 1: Both parties start enhancement and exchange commits
        let alice_commit = alice.ko_start_enhancement(&ss).unwrap();
        let bob_commit = bob.ko_start_enhancement(&ss).unwrap();

        // Step 2: Process received commits and create reveals
        let alice_reveal = alice.ko_process_commit(&bob_commit).unwrap();
        let bob_reveal = bob.ko_process_commit(&alice_commit).unwrap();

        // Step 3: Finalize with received reveals
        alice.ko_finalize(&bob_reveal).unwrap();
        bob.ko_finalize(&alice_reveal).unwrap();

        // Both sessions should now have enhanced Ko
        assert!(alice.is_ko_enhanced());
        assert!(bob.is_ko_enhanced());

        // Verify they can still communicate
        let plaintext = b"Post-enhancement message!";
        let msg = alice.send(plaintext).unwrap();
        let decrypted = bob.receive(&msg).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ko_enhancement_prevents_double_enhancement() {
        let (alice, bob, ss) = create_test_sessions();

        // Complete full enhancement
        let alice_commit = alice.ko_start_enhancement(&ss).unwrap();
        let bob_commit = bob.ko_start_enhancement(&ss).unwrap();
        let alice_reveal = alice.ko_process_commit(&bob_commit).unwrap();
        let bob_reveal = bob.ko_process_commit(&alice_commit).unwrap();
        alice.ko_finalize(&bob_reveal).unwrap();
        bob.ko_finalize(&alice_reveal).unwrap();

        // Starting again should fail (already enhanced)
        let result = alice.ko_start_enhancement(&ss);
        assert!(result.is_err());
    }

    #[test]
    fn test_ko_enhancement_commit_mismatch() {
        let (alice, bob, ss) = create_test_sessions();

        // Start enhancement
        let _alice_commit = alice.ko_start_enhancement(&ss).unwrap();
        let bob_commit = bob.ko_start_enhancement(&ss).unwrap();

        // Alice processes Bob's commit
        let _alice_reveal = alice.ko_process_commit(&bob_commit).unwrap();

        // Create a fake reveal with wrong entropy
        let fake_reveal = KoRevealMessage {
            reveal_ct: vec![0u8; 48], // Wrong ciphertext
        };

        // Finalization should fail due to decryption error or commit mismatch
        let result = alice.ko_finalize(&fake_reveal);
        assert!(result.is_err());
    }
}
