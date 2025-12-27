package io.dice52;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.modes.ChaCha20Poly1305;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.*;
import org.bouncycastle.pqc.crypto.crystals.kyber.*;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Session state for a Dice52 PQ ratchet session.
 */
public class Session {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final ReentrantLock lock = new ReentrantLock();

    private byte[] rk; // Root key
    private byte[] ko; // Ordering key
    private byte[] cks; // Chain key send
    private byte[] ckr; // Chain key receive

    private long ns; // Send message counter
    private long nr; // Receive message counter
    private long epoch; // Epoch counter

    private KyberPublicKeyParameters kemPub; // Our KEM public key
    private KyberPrivateKeyParameters kemPriv; // Our KEM private key
    private X25519PublicKeyParameters ecdhPub; // Our X25519 public key for hybrid KEM
    private X25519PrivateKeyParameters ecdhPriv; // Our X25519 private key for hybrid KEM
    private DilithiumPublicKeyParameters idPub; // Our identity public key
    private DilithiumPrivateKeyParameters idPriv; // Our identity private key
    private DilithiumPublicKeyParameters peerId; // Peer's identity public key

    private final int sessionId;

    private Types.KoEnhancementState koEnhancement;
    private boolean koEnhanced;
    private final boolean isInitiator;

    private Types.ParanoidConfig paranoidConfig;
    private long lastKoEnhancedEpoch;
    private boolean pendingKoReenhance;
    private byte[] lastSharedSecret;

    public Session(
            int sessionId,
            byte[] rk,
            byte[] ko,
            byte[] cks,
            byte[] ckr,
            KyberPublicKeyParameters kemPub,
            KyberPrivateKeyParameters kemPriv,
            DilithiumPublicKeyParameters idPub,
            DilithiumPrivateKeyParameters idPriv,
            DilithiumPublicKeyParameters peerId,
            boolean isInitiator) {
        this.sessionId = sessionId;
        this.rk = rk;
        this.ko = ko;
        this.cks = cks;
        this.ckr = ckr;
        this.kemPub = kemPub;
        this.kemPriv = kemPriv;

        // Generate initial X25519 keypair for hybrid KEM
        AsymmetricCipherKeyPair ecdhKeyPair = Handshake.generateX25519Keypair();
        this.ecdhPub = (X25519PublicKeyParameters) ecdhKeyPair.getPublic();
        this.ecdhPriv = (X25519PrivateKeyParameters) ecdhKeyPair.getPrivate();

        this.idPub = idPub;
        this.idPriv = idPriv;
        this.peerId = peerId;
        this.isInitiator = isInitiator;

        this.ns = 0;
        this.nr = 0;
        this.epoch = 0;

        this.koEnhancement = null;
        this.koEnhanced = false;

        this.paranoidConfig = new Types.ParanoidConfig();
        this.lastKoEnhancedEpoch = 0;
        this.pendingKoReenhance = false;
        this.lastSharedSecret = null;
    }

    /**
     * Create a new session with explicit X25519 keys for hybrid KEM.
     */
    public Session(
            int sessionId,
            byte[] rk,
            byte[] ko,
            byte[] cks,
            byte[] ckr,
            KyberPublicKeyParameters kemPub,
            KyberPrivateKeyParameters kemPriv,
            X25519PublicKeyParameters ecdhPub,
            X25519PrivateKeyParameters ecdhPriv,
            X25519PublicKeyParameters peerEcdhPub,
            DilithiumPublicKeyParameters idPub,
            DilithiumPrivateKeyParameters idPriv,
            DilithiumPublicKeyParameters peerId,
            boolean isInitiator) {
        this.sessionId = sessionId;
        this.rk = rk;
        this.ko = ko;
        this.cks = cks;
        this.ckr = ckr;
        this.kemPub = kemPub;
        this.kemPriv = kemPriv;

        // Use provided X25519 keys
        this.ecdhPub = ecdhPub;
        this.ecdhPriv = ecdhPriv;
        // peerEcdhPub is stored for future hybrid ratchets

        this.idPub = idPub;
        this.idPriv = idPriv;
        this.peerId = peerId;
        this.isInitiator = isInitiator;

        this.ns = 0;
        this.nr = 0;
        this.epoch = 0;

        this.koEnhancement = null;
        this.koEnhanced = false;

        this.paranoidConfig = new Types.ParanoidConfig();
        this.lastKoEnhancedEpoch = 0;
        this.pendingKoReenhance = false;
        this.lastSharedSecret = null;
    }

    public void setParanoidMode(Types.ParanoidConfig config) throws Dice52Exception.ConfigError {
        config.validate();
        lock.lock();
        try {
            this.paranoidConfig = config;
        } finally {
            lock.unlock();
        }
    }

    public Types.ParanoidConfig getParanoidConfig() {
        lock.lock();
        try {
            return paranoidConfig;
        } finally {
            lock.unlock();
        }
    }

    public boolean isParanoidMode() {
        lock.lock();
        try {
            return paranoidConfig.enabled;
        } finally {
            lock.unlock();
        }
    }

    public boolean needsKoReenhancement() {
        lock.lock();
        try {
            return pendingKoReenhance;
        } finally {
            lock.unlock();
        }
    }

    private int getMaxMessagesPerEpoch() {
        if (paranoidConfig.enabled && paranoidConfig.maxMessagesPerEpoch > 0) {
            return paranoidConfig.maxMessagesPerEpoch;
        }
        return Constants.DEFAULT_MAX_MESSAGES_PER_EPOCH;
    }

    /**
     * Send encrypts and sends a message (Section 11).
     */
    public Types.Message send(byte[] pt) throws Dice52Exception.EpochExhausted {
        lock.lock();
        try {
            // Section 14: Enforce epoch limit
            int maxMessages = getMaxMessagesPerEpoch();
            if (ns >= maxMessages) {
                throw new Dice52Exception.EpochExhausted("Epoch exhausted: rekey required");
            }

            byte[][] ckMk = Kdf.ckToMk(cks, ko, ns, (byte) 0, rk);
            cks = ckMk[0];
            byte[] mk = ckMk[1];

            // Section 11.1: AD must include version, epoch, message number, direction
            Types.Header header = new Types.Header(Constants.VERSION, epoch, ns, "send");
            byte[] ad = header.toJson();

            byte[] ct = Crypto.encrypt(mk, sessionId, epoch, ns, ad, pt);
            Crypto.zeroBytes(mk);
            ns++;

            return new Types.Message(
                    Base64.getEncoder().encodeToString(ad),
                    Base64.getEncoder().encodeToString(ct));
        } finally {
            lock.unlock();
        }
    }

    /**
     * Receive decrypts a received message (Section 12).
     */
    public byte[] receive(Types.Message msg) throws Dice52Exception {
        lock.lock();
        try {
            byte[] ad = Base64.getDecoder().decode(msg.header);
            Types.Header header = Types.Header.fromJson(ad);

            // Section 16: Message numbers must be monotonically increasing
            if (header.msgNum < nr) {
                throw new Dice52Exception.ReplayDetected("Message number too low");
            }

            byte[] ct = Base64.getDecoder().decode(msg.body);

            // Enforce epoch match on receive
            if (header.epoch != epoch) {
                throw new Dice52Exception.EpochMismatch("Epoch mismatch");
            }

            // Derive MK using message number from header
            byte[][] ckMk = Kdf.ckToMk(ckr, ko, header.msgNum, (byte) 0, rk);
            ckr = ckMk[0];
            byte[] mk = ckMk[1];

            // Reconstruct AD with send direction for decryption
            Types.Header recvHeader = new Types.Header(header.version, header.epoch, header.msgNum, "send");
            byte[] recvAd = recvHeader.toJson();

            byte[] pt = Crypto.decrypt(mk, sessionId, header.epoch, header.msgNum, recvAd, ct);
            Crypto.zeroBytes(mk);

            nr = header.msgNum + 1;
            return pt;
        } finally {
            lock.unlock();
        }
    }

    private void applyRatchet(byte[] ss, boolean asInitiator) {
        // RK = HKDF(RK || SS || Ko, "Dice52-RK-Ratchet")
        byte[] combined = Kdf.concat(rk, ss, ko);
        rk = Kdf.hkdfExpand(combined, Constants.RK_RATCHET_INFO);

        // Ko = HKDF(RK, "Dice52-Ko")
        ko = Kdf.hkdfExpand(rk, Constants.KO_INFO);

        // Reinitialize chain keys
        byte[][] chainKeys = Kdf.initChainKeys(rk, ko);
        if (asInitiator) {
            // Ratchet initiator: CKs sends, CKr receives
            cks = chainKeys[0];
            ckr = chainKeys[1];
        } else {
            // Ratchet responder: swap keys (responder's send = initiator's receive)
            cks = chainKeys[1];
            ckr = chainKeys[0];
        }
        ns = 0;
        nr = 0;
        epoch++;

        // Paranoid mode: Check if Ko re-enhancement is needed
        if (paranoidConfig.enabled && paranoidConfig.koReenhanceInterval > 0) {
            long epochsSinceLastEnhance = epoch - lastKoEnhancedEpoch;
            if (epochsSinceLastEnhance >= paranoidConfig.koReenhanceInterval) {
                pendingKoReenhance = true;
                lastSharedSecret = ss.clone();
            }
        }
    }

    /**
     * Initiate a hybrid PQ ratchet with Dilithium signature (Section 12.2).
     */
    public Types.RatchetMessage initiateRatchet() {
        lock.lock();
        try {
            // Generate new Kyber key pair
            AsymmetricCipherKeyPair keypair = Handshake.generateKemKeypair();
            kemPub = (KyberPublicKeyParameters) keypair.getPublic();
            kemPriv = (KyberPrivateKeyParameters) keypair.getPrivate();

            // Generate new X25519 key pair
            AsymmetricCipherKeyPair ecdhKeypair = Handshake.generateX25519Keypair();
            ecdhPub = (X25519PublicKeyParameters) ecdhKeypair.getPublic();
            ecdhPriv = (X25519PrivateKeyParameters) ecdhKeypair.getPrivate();

            // Get public key bytes
            byte[] pubKeyBytes = kemPub.getEncoded();
            byte[] ecdhPubBytes = ecdhPub.getEncoded();

            // Sign: context || KEMPub || ECDHPub
            byte[] toSign = Kdf.concat(Constants.SIG_CONTEXT, pubKeyBytes, ecdhPubBytes);

            DilithiumSigner signer = new DilithiumSigner();
            signer.init(true, idPriv);
            byte[] signature = signer.generateSignature(toSign);

            return new Types.RatchetMessage(pubKeyBytes, ecdhPubBytes, signature, null);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Respond to initiator's hybrid ratchet message (Section 12.3).
     */
    public Types.RatchetMessage respondRatchet(Types.RatchetMessage msg)
            throws Dice52Exception.InvalidRatchetSignature, Dice52Exception.KemError {
        lock.lock();
        try {
            if (msg.pubKey == null || msg.sig == null || msg.ecdhPub == null) {
                throw new Dice52Exception.KemError("Missing public key, signature, or ECDH key");
            }

            // Verify signature over SigContext || KEMPub || ECDHPub
            byte[] toVerify = Kdf.concat(Constants.SIG_CONTEXT, msg.pubKey, msg.ecdhPub);

            DilithiumSigner verifier = new DilithiumSigner();
            verifier.init(false, peerId);

            if (!verifier.verifySignature(toVerify, msg.sig)) {
                throw new Dice52Exception.InvalidRatchetSignature("Ratchet signature verification failed");
            }

            // Parse peer's public keys
            KyberPublicKeyParameters peerKemPub = new KyberPublicKeyParameters(Handshake.KYBER_PARAMS, msg.pubKey);
            X25519PublicKeyParameters peerEcdhPub = new X25519PublicKeyParameters(msg.ecdhPub, 0);

            // Generate ephemeral X25519 key pair for response
            AsymmetricCipherKeyPair respEcdhKeypair = Handshake.generateX25519Keypair();
            X25519PublicKeyParameters respEcdhPub = (X25519PublicKeyParameters) respEcdhKeypair.getPublic();
            X25519PrivateKeyParameters respEcdhPriv = (X25519PrivateKeyParameters) respEcdhKeypair.getPrivate();

            // Kyber encapsulation
            KyberKEMGenerator kemGen = new KyberKEMGenerator(SECURE_RANDOM);
            org.bouncycastle.crypto.SecretWithEncapsulation encap = kemGen.generateEncapsulated(peerKemPub);

            // X25519 key agreement
            byte[] ssEcdh = Handshake.x25519SharedSecret(respEcdhPriv, peerEcdhPub);

            // Derive hybrid shared secret
            byte[] ssHybrid = Kdf.deriveHybridSharedSecret(encap.getSecret(), ssEcdh);

            // Apply ratchet with hybrid shared secret (responder)
            applyRatchet(ssHybrid, false);

            return new Types.RatchetMessage(null, respEcdhPub.getEncoded(), null, encap.getEncapsulation());
        } finally {
            lock.unlock();
        }
    }

    /**
     * Finalize the hybrid ratchet on the initiator side (Section 12.4).
     */
    public void finalizeRatchet(Types.RatchetMessage msg) throws Dice52Exception.KemError {
        lock.lock();
        try {
            if (msg.ct == null || msg.ecdhPub == null) {
                throw new Dice52Exception.KemError("Missing ciphertext or ECDH key");
            }

            // Decapsulate Kyber ciphertext
            KyberKEMExtractor extractor = new KyberKEMExtractor(kemPriv);
            byte[] ssPq = extractor.extractSecret(msg.ct);

            // X25519 key agreement with responder's ephemeral public key
            X25519PublicKeyParameters peerEcdhPub = new X25519PublicKeyParameters(msg.ecdhPub, 0);
            byte[] ssEcdh = Handshake.x25519SharedSecret(ecdhPriv, peerEcdhPub);

            // Derive hybrid shared secret
            byte[] ssHybrid = Kdf.deriveHybridSharedSecret(ssPq, ssEcdh);

            applyRatchet(ssHybrid, true); // Initiator
        } finally {
            lock.unlock();
        }
    }

    public long getEpoch() {
        lock.lock();
        try {
            return epoch;
        } finally {
            lock.unlock();
        }
    }

    public int getSessionId() {
        return sessionId;
    }

    public boolean isKoEnhanced() {
        lock.lock();
        try {
            return koEnhanced;
        } finally {
            lock.unlock();
        }
    }

    // =========================================================================
    // Ko Enhancement Protocol (Section 7.1)
    // =========================================================================

    /**
     * Start Ko enhancement: generate local entropy and create commit message.
     */
    public Types.KoCommitMessage koStartEnhancement(byte[] ss) throws Dice52Exception.KoEnhancementError {
        lock.lock();
        try {
            if (koEnhanced) {
                throw new Dice52Exception.KoEnhancementError("Ko already enhanced");
            }

            // Generate local entropy
            byte[] localEntropy = Crypto.randBytes(32);

            // Derive temporary key
            byte[] tk = Kdf.deriveKoCommitKey(ss);

            // Create commitment
            byte[] localCommit = Kdf.commitEntropy(sessionId, localEntropy);

            // Encrypt commitment with TK (nonce = 0 for commit)
            byte[] nonce = new byte[12];
            byte[] commitCt = encryptWithAead(tk, nonce, "ko-commit".getBytes(), localCommit);

            // Store state
            koEnhancement = new Types.KoEnhancementState();
            koEnhancement.tk = tk;
            koEnhancement.localEntropy = localEntropy;
            koEnhancement.localCommit = localCommit;

            return new Types.KoCommitMessage(commitCt);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Process received commit and create reveal message.
     */
    public Types.KoRevealMessage koProcessCommit(Types.KoCommitMessage peerCommitMsg)
            throws Dice52Exception.KoEnhancementError {
        lock.lock();
        try {
            if (koEnhancement == null) {
                throw new Dice52Exception.KoEnhancementError("Enhancement not started");
            }

            // Decrypt peer's commit
            byte[] nonce = new byte[12];
            byte[] peerCommit = decryptWithAead(koEnhancement.tk, nonce,
                    "ko-commit".getBytes(), peerCommitMsg.commitCt);

            if (peerCommit.length != 32) {
                throw new Dice52Exception.KoEnhancementError("Invalid commit length");
            }

            koEnhancement.peerCommit = peerCommit;

            // Create reveal (encrypt our entropy with nonce = 1)
            byte[] revealNonce = new byte[12];
            revealNonce[11] = 1;
            byte[] revealCt = encryptWithAead(koEnhancement.tk, revealNonce,
                    "ko-reveal".getBytes(), koEnhancement.localEntropy);

            return new Types.KoRevealMessage(revealCt);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Finalize Ko enhancement with peer's reveal.
     */
    public void koFinalize(Types.KoRevealMessage peerRevealMsg)
            throws Dice52Exception.KoEnhancementError, Dice52Exception.KoCommitMismatch {
        lock.lock();
        try {
            if (koEnhancement == null) {
                throw new Dice52Exception.KoEnhancementError("Enhancement not started");
            }

            if (koEnhancement.peerCommit == null) {
                throw new Dice52Exception.KoEnhancementError("Peer commit not received");
            }

            // Decrypt peer's reveal
            byte[] revealNonce = new byte[12];
            revealNonce[11] = 1;
            byte[] peerEntropy = decryptWithAead(koEnhancement.tk, revealNonce,
                    "ko-reveal".getBytes(), peerRevealMsg.revealCt);

            if (peerEntropy.length != 32) {
                throw new Dice52Exception.KoEnhancementError("Invalid reveal length");
            }

            // Verify commit
            if (!Kdf.verifyCommit(sessionId, peerEntropy, koEnhancement.peerCommit)) {
                throw new Dice52Exception.KoCommitMismatch("Ko commit verification failed");
            }

            // Determine initiator/responder entropy order
            byte[] rInitiator, rResponder;
            if (isInitiator) {
                rInitiator = koEnhancement.localEntropy;
                rResponder = peerEntropy;
            } else {
                rInitiator = peerEntropy;
                rResponder = koEnhancement.localEntropy;
            }

            // Derive enhanced Ko
            ko = Kdf.deriveEnhancedKo(ko, rInitiator, rResponder);

            // Clear sensitive state
            koEnhancement.zero();
            koEnhancement = null;
            koEnhanced = true;

            // Track when Ko was last enhanced
            lastKoEnhancedEpoch = epoch;
            pendingKoReenhance = false;
        } finally {
            lock.unlock();
        }
    }

    // =========================================================================
    // Paranoid Mode Ko Re-enhancement (Section 7.2)
    // =========================================================================

    /**
     * Start Ko re-enhancement during paranoid mode.
     */
    public Types.KoCommitMessage koStartReenhancement() throws Dice52Exception.KoEnhancementError {
        lock.lock();
        try {
            if (!paranoidConfig.enabled) {
                throw new Dice52Exception.KoEnhancementError("Paranoid mode not enabled");
            }

            if (!pendingKoReenhance) {
                throw new Dice52Exception.KoEnhancementError("Ko re-enhancement not needed");
            }

            if (lastSharedSecret == null) {
                throw new Dice52Exception.KoEnhancementError("No shared secret available");
            }

            // Generate local entropy
            byte[] localEntropy = Crypto.randBytes(32);

            // Derive temporary key
            byte[] tk = Kdf.deriveKoCommitKey(lastSharedSecret);

            // Create commitment
            byte[] localCommit = Kdf.commitEntropy(sessionId, localEntropy);

            // Encrypt commitment
            byte[] nonce = new byte[12];
            byte[] commitCt = encryptWithAead(tk, nonce,
                    "ko-reenhance-commit".getBytes(), localCommit);

            // Store state
            koEnhancement = new Types.KoEnhancementState();
            koEnhancement.tk = tk;
            koEnhancement.localEntropy = localEntropy;
            koEnhancement.localCommit = localCommit;

            return new Types.KoCommitMessage(commitCt);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Process received re-enhancement commit.
     */
    public Types.KoRevealMessage koProcessReenhanceCommit(Types.KoCommitMessage peerCommitMsg)
            throws Dice52Exception.KoEnhancementError {
        lock.lock();
        try {
            if (koEnhancement == null) {
                throw new Dice52Exception.KoEnhancementError("Re-enhancement not started");
            }

            // Decrypt peer's commit
            byte[] nonce = new byte[12];
            byte[] peerCommit = decryptWithAead(koEnhancement.tk, nonce,
                    "ko-reenhance-commit".getBytes(), peerCommitMsg.commitCt);

            if (peerCommit.length != 32) {
                throw new Dice52Exception.KoEnhancementError("Invalid commit length");
            }

            koEnhancement.peerCommit = peerCommit;

            // Create reveal
            byte[] revealNonce = new byte[12];
            revealNonce[11] = 1;
            byte[] revealCt = encryptWithAead(koEnhancement.tk, revealNonce,
                    "ko-reenhance-reveal".getBytes(), koEnhancement.localEntropy);

            return new Types.KoRevealMessage(revealCt);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Finalize Ko re-enhancement.
     */
    public void koFinalizeReenhancement(Types.KoRevealMessage peerRevealMsg)
            throws Dice52Exception.KoEnhancementError, Dice52Exception.KoCommitMismatch {
        lock.lock();
        try {
            if (koEnhancement == null) {
                throw new Dice52Exception.KoEnhancementError("Re-enhancement not started");
            }

            if (koEnhancement.peerCommit == null) {
                throw new Dice52Exception.KoEnhancementError("Peer commit not received");
            }

            // Decrypt peer's reveal
            byte[] revealNonce = new byte[12];
            revealNonce[11] = 1;
            byte[] peerEntropy = decryptWithAead(koEnhancement.tk, revealNonce,
                    "ko-reenhance-reveal".getBytes(), peerRevealMsg.revealCt);

            if (peerEntropy.length != 32) {
                throw new Dice52Exception.KoEnhancementError("Invalid reveal length");
            }

            // Verify commit
            if (!Kdf.verifyCommit(sessionId, peerEntropy, koEnhancement.peerCommit)) {
                throw new Dice52Exception.KoCommitMismatch("Ko re-enhancement commit verification failed");
            }

            // Determine initiator/responder entropy order
            byte[] rInitiator, rResponder;
            if (isInitiator) {
                rInitiator = koEnhancement.localEntropy;
                rResponder = peerEntropy;
            } else {
                rInitiator = peerEntropy;
                rResponder = koEnhancement.localEntropy;
            }

            // Derive re-enhanced Ko
            ko = Kdf.deriveEnhancedKo(ko, rInitiator, rResponder);

            // Clear state
            koEnhancement.zero();
            koEnhancement = null;
            lastKoEnhancedEpoch = epoch;
            pendingKoReenhance = false;
            Crypto.zeroBytes(lastSharedSecret);
            lastSharedSecret = null;
        } finally {
            lock.unlock();
        }
    }

    // =========================================================================
    // Helper methods for AEAD encryption
    // =========================================================================

    private byte[] encryptWithAead(byte[] key, byte[] nonce, byte[] ad, byte[] pt)
            throws Dice52Exception.KoEnhancementError {
        try {
            ChaCha20Poly1305 cipher = new ChaCha20Poly1305();
            cipher.init(true, new AEADParameters(new KeyParameter(key), 128, nonce, ad));
            byte[] output = new byte[cipher.getOutputSize(pt.length)];
            int len = cipher.processBytes(pt, 0, pt.length, output, 0);
            cipher.doFinal(output, len);
            return output;
        } catch (Exception e) {
            throw new Dice52Exception.KoEnhancementError("Encryption failed: " + e.getMessage());
        }
    }

    private byte[] decryptWithAead(byte[] key, byte[] nonce, byte[] ad, byte[] ct)
            throws Dice52Exception.KoEnhancementError {
        try {
            ChaCha20Poly1305 cipher = new ChaCha20Poly1305();
            cipher.init(false, new AEADParameters(new KeyParameter(key), 128, nonce, ad));
            byte[] output = new byte[cipher.getOutputSize(ct.length)];
            int len = cipher.processBytes(ct, 0, ct.length, output, 0);
            cipher.doFinal(output, len);
            return output;
        } catch (Exception e) {
            throw new Dice52Exception.KoEnhancementError("Decryption failed: " + e.getMessage());
        }
    }
}
