package io.dice52;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.pqc.crypto.crystals.dilithium.*;
import org.bouncycastle.pqc.crypto.crystals.kyber.*;

import java.security.SecureRandom;

/**
 * Handshake protocol using hybrid KEM (Kyber768 + X25519) and Dilithium3.
 */
public class Handshake {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    // Kyber768 parameters
    public static final KyberParameters KYBER_PARAMS = KyberParameters.kyber768;

    // Dilithium3 parameters
    public static final DilithiumParameters DILITHIUM_PARAMS = DilithiumParameters.dilithium3;

    private Handshake() {
        // Utility class
    }

    /**
     * Generate a new X25519 key pair.
     * 
     * @return AsymmetricCipherKeyPair containing public and private keys
     */
    public static AsymmetricCipherKeyPair generateX25519Keypair() {
        X25519KeyPairGenerator gen = new X25519KeyPairGenerator();
        gen.init(new X25519KeyGenerationParameters(SECURE_RANDOM));
        return gen.generateKeyPair();
    }

    /**
     * Compute X25519 shared secret.
     */
    public static byte[] x25519SharedSecret(X25519PrivateKeyParameters ourPriv, X25519PublicKeyParameters peerPub) {
        X25519Agreement agreement = new X25519Agreement();
        agreement.init(ourPriv);
        byte[] secret = new byte[agreement.getAgreementSize()];
        agreement.calculateAgreement(peerPub, secret, 0);
        return secret;
    }

    /**
     * Result of hybrid encapsulation.
     */
    public static class HybridEncapsulationResult {
        public final byte[] hybridSharedSecret;
        public final byte[] kyberCiphertext;
        public final byte[] ecdhPub;
        public final X25519PrivateKeyParameters ecdhPriv;

        public HybridEncapsulationResult(byte[] hybridSharedSecret, byte[] kyberCiphertext,
                byte[] ecdhPub, X25519PrivateKeyParameters ecdhPriv) {
            this.hybridSharedSecret = hybridSharedSecret;
            this.kyberCiphertext = kyberCiphertext;
            this.ecdhPub = ecdhPub;
            this.ecdhPriv = ecdhPriv;
        }
    }

    /**
     * Generate a new Kyber768 key pair.
     * 
     * @return AsymmetricCipherKeyPair containing public and private keys
     */
    public static AsymmetricCipherKeyPair generateKemKeypair() {
        KyberKeyPairGenerator gen = new KyberKeyPairGenerator();
        gen.init(new KyberKeyGenerationParameters(SECURE_RANDOM, KYBER_PARAMS));
        return gen.generateKeyPair();
    }

    /**
     * Generate a new Dilithium3 key pair.
     * 
     * @return AsymmetricCipherKeyPair containing public and private keys
     */
    public static AsymmetricCipherKeyPair generateSigningKeypair() {
        DilithiumKeyPairGenerator gen = new DilithiumKeyPairGenerator();
        gen.init(new DilithiumKeyGenerationParameters(SECURE_RANDOM, DILITHIUM_PARAMS));
        return gen.generateKeyPair();
    }

    /**
     * Initiator encapsulate: Alice encapsulates to Bob's public key (Section 7).
     * 
     * @return EncapsulationResult containing shared secret and ciphertext
     */
    public static EncapsulationResult initiatorEncapsulate(KyberPublicKeyParameters peerPub) {
        KyberKEMGenerator kemGen = new KyberKEMGenerator(SECURE_RANDOM);
        org.bouncycastle.crypto.SecretWithEncapsulation encap = kemGen.generateEncapsulated(peerPub);
        return new EncapsulationResult(encap.getSecret(), encap.getEncapsulation());
    }

    /**
     * Responder decapsulate: Bob decapsulates using his private key (Section 7).
     */
    public static byte[] responderDecapsulate(KyberPrivateKeyParameters ourPriv, byte[] ct) {
        KyberKEMExtractor extractor = new KyberKEMExtractor(ourPriv);
        return extractor.extractSecret(ct);
    }

    /**
     * Initiator handshake: hybrid encapsulation to peer's public keys and sign
     * (Section 6.2).
     * 
     * @return HandshakeResult containing message, hybrid shared secret, and ECDH
     *         private key
     */
    public static HandshakeResult initiatorHandshake(
            KyberPublicKeyParameters peerKem,
            X25519PublicKeyParameters peerEcdh,
            DilithiumPrivateKeyParameters idPriv) {
        // Generate ephemeral X25519 key pair
        AsymmetricCipherKeyPair ecdhKeyPair = generateX25519Keypair();
        X25519PublicKeyParameters ecdhPub = (X25519PublicKeyParameters) ecdhKeyPair.getPublic();
        X25519PrivateKeyParameters ecdhPriv = (X25519PrivateKeyParameters) ecdhKeyPair.getPrivate();

        // Kyber encapsulation
        EncapsulationResult encapResult = initiatorEncapsulate(peerKem);

        // X25519 key agreement
        byte[] ssEcdh = x25519SharedSecret(ecdhPriv, peerEcdh);

        // Derive hybrid shared secret
        byte[] ssHybrid = Kdf.deriveHybridSharedSecret(encapResult.sharedSecret, ssEcdh);

        // Sign: context || ciphertext || ecdhPub
        byte[] ecdhPubBytes = ecdhPub.getEncoded();
        byte[] toSign = Kdf.concat(Constants.SIG_CONTEXT, encapResult.ciphertext, ecdhPubBytes);

        DilithiumSigner signer = new DilithiumSigner();
        signer.init(true, idPriv);
        byte[] signature = signer.generateSignature(toSign);

        Types.HandshakeMessage msg = new Types.HandshakeMessage(encapResult.ciphertext, ecdhPubBytes, signature);
        return new HandshakeResult(msg, ssHybrid, ecdhPriv);
    }

    /**
     * Responder handshake: verify signature and hybrid decapsulation (Section 6.3).
     */
    public static byte[] responderHandshake(
            Types.HandshakeMessage msg,
            KyberPrivateKeyParameters kemPriv,
            X25519PrivateKeyParameters ecdhPriv,
            DilithiumPublicKeyParameters peerId)
            throws Dice52Exception.InvalidHandshakeSignature {
        // Verify signature over context || ciphertext || ecdhPub
        byte[] toVerify = Kdf.concat(Constants.SIG_CONTEXT, msg.kyberCt, msg.ecdhPub);

        DilithiumSigner verifier = new DilithiumSigner();
        verifier.init(false, peerId);

        if (!verifier.verifySignature(toVerify, msg.sig)) {
            throw new Dice52Exception.InvalidHandshakeSignature("Handshake signature verification failed");
        }

        // Decapsulate Kyber
        byte[] ssPq = responderDecapsulate(kemPriv, msg.kyberCt);

        // X25519 key agreement
        X25519PublicKeyParameters peerEcdhPub = new X25519PublicKeyParameters(msg.ecdhPub, 0);
        byte[] ssEcdh = x25519SharedSecret(ecdhPriv, peerEcdhPub);

        // Derive hybrid shared secret
        return Kdf.deriveHybridSharedSecret(ssPq, ssEcdh);
    }

    /**
     * Initiator hybrid encapsulate: Alice encapsulates to Bob's public keys.
     */
    public static HybridEncapsulationResult initiatorHybridEncapsulate(
            KyberPublicKeyParameters peerKem,
            X25519PublicKeyParameters peerEcdh) {
        // Generate ephemeral X25519 key pair
        AsymmetricCipherKeyPair ecdhKeyPair = generateX25519Keypair();
        X25519PublicKeyParameters ecdhPub = (X25519PublicKeyParameters) ecdhKeyPair.getPublic();
        X25519PrivateKeyParameters ecdhPriv = (X25519PrivateKeyParameters) ecdhKeyPair.getPrivate();

        // Kyber encapsulation
        EncapsulationResult encapResult = initiatorEncapsulate(peerKem);

        // X25519 key agreement
        byte[] ssEcdh = x25519SharedSecret(ecdhPriv, peerEcdh);

        // Derive hybrid shared secret
        byte[] ssHybrid = Kdf.deriveHybridSharedSecret(encapResult.sharedSecret, ssEcdh);

        return new HybridEncapsulationResult(ssHybrid, encapResult.ciphertext, ecdhPub.getEncoded(), ecdhPriv);
    }

    /**
     * Responder hybrid decapsulate: Bob decapsulates using his private keys.
     */
    public static byte[] responderHybridDecapsulate(
            KyberPrivateKeyParameters kemPriv,
            X25519PrivateKeyParameters ecdhPriv,
            byte[] kyberCt,
            byte[] peerEcdhPub) {
        // Decapsulate Kyber
        byte[] ssPq = responderDecapsulate(kemPriv, kyberCt);

        // X25519 key agreement
        X25519PublicKeyParameters peerPub = new X25519PublicKeyParameters(peerEcdhPub, 0);
        byte[] ssEcdh = x25519SharedSecret(ecdhPriv, peerPub);

        // Derive hybrid shared secret
        return Kdf.deriveHybridSharedSecret(ssPq, ssEcdh);
    }

    /**
     * Result of KEM encapsulation.
     */
    public static class EncapsulationResult {
        public final byte[] sharedSecret;
        public final byte[] ciphertext;

        public EncapsulationResult(byte[] sharedSecret, byte[] ciphertext) {
            this.sharedSecret = sharedSecret;
            this.ciphertext = ciphertext;
        }
    }

    /**
     * Result of handshake initiation.
     */
    public static class HandshakeResult {
        public final Types.HandshakeMessage message;
        public final byte[] sharedSecret;
        public final X25519PrivateKeyParameters ecdhPriv;

        public HandshakeResult(Types.HandshakeMessage message, byte[] sharedSecret,
                X25519PrivateKeyParameters ecdhPriv) {
            this.message = message;
            this.sharedSecret = sharedSecret;
            this.ecdhPriv = ecdhPriv;
        }
    }
}
