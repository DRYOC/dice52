package io.dice52;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.crypto.crystals.dilithium.*;
import org.bouncycastle.pqc.crypto.crystals.kyber.*;

import java.security.SecureRandom;

/**
 * Handshake protocol using Kyber768 and Dilithium3.
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
     * Initiator handshake: encapsulate to peer's KEM public key and sign.
     * 
     * @return HandshakeResult containing message and shared secret
     */
    public static HandshakeResult initiatorHandshake(
            KyberPublicKeyParameters peerKem,
            DilithiumPrivateKeyParameters idPriv) {
        // Encapsulate to peer's public key
        EncapsulationResult encapResult = initiatorEncapsulate(peerKem);

        // Sign: context || ciphertext
        byte[] toSign = Kdf.concat(Constants.SIG_CONTEXT, encapResult.ciphertext);

        DilithiumSigner signer = new DilithiumSigner();
        signer.init(true, idPriv);
        byte[] signature = signer.generateSignature(toSign);

        Types.HandshakeMessage msg = new Types.HandshakeMessage(encapResult.ciphertext, signature);
        return new HandshakeResult(msg, encapResult.sharedSecret);
    }

    /**
     * Responder handshake: verify signature and decapsulate.
     */
    public static byte[] responderHandshake(
            Types.HandshakeMessage msg,
            KyberPrivateKeyParameters kemPriv,
            DilithiumPublicKeyParameters peerId)
            throws Dice52Exception.InvalidHandshakeSignature {
        // Verify signature
        byte[] toVerify = Kdf.concat(Constants.SIG_CONTEXT, msg.kyberCt);

        DilithiumSigner verifier = new DilithiumSigner();
        verifier.init(false, peerId);

        if (!verifier.verifySignature(toVerify, msg.sig)) {
            throw new Dice52Exception.InvalidHandshakeSignature("Handshake signature verification failed");
        }

        // Decapsulate
        return responderDecapsulate(kemPriv, msg.kyberCt);
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

        public HandshakeResult(Types.HandshakeMessage message, byte[] sharedSecret) {
            this.message = message;
            this.sharedSecret = sharedSecret;
        }
    }
}
