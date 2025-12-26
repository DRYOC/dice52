package io.dice52;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.crypto.crystals.dilithium.*;
import org.bouncycastle.pqc.crypto.crystals.kyber.*;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for Dice52 session functionality.
 */
class SessionTest {

    @BeforeAll
    static void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static Object[] createTestSessions() {
        // Generate KEM key pairs
        AsymmetricCipherKeyPair kemKeysA = Handshake.generateKemKeypair();
        KyberPublicKeyParameters kemPubA = (KyberPublicKeyParameters) kemKeysA.getPublic();
        KyberPrivateKeyParameters kemPrivA = (KyberPrivateKeyParameters) kemKeysA.getPrivate();

        AsymmetricCipherKeyPair kemKeysB = Handshake.generateKemKeypair();
        KyberPublicKeyParameters kemPubB = (KyberPublicKeyParameters) kemKeysB.getPublic();
        KyberPrivateKeyParameters kemPrivB = (KyberPrivateKeyParameters) kemKeysB.getPrivate();

        // Generate identity key pairs
        AsymmetricCipherKeyPair idKeysA = Handshake.generateSigningKeypair();
        DilithiumPublicKeyParameters idPubA = (DilithiumPublicKeyParameters) idKeysA.getPublic();
        DilithiumPrivateKeyParameters idPrivA = (DilithiumPrivateKeyParameters) idKeysA.getPrivate();

        AsymmetricCipherKeyPair idKeysB = Handshake.generateSigningKeypair();
        DilithiumPublicKeyParameters idPubB = (DilithiumPublicKeyParameters) idKeysB.getPublic();
        DilithiumPrivateKeyParameters idPrivB = (DilithiumPrivateKeyParameters) idKeysB.getPrivate();

        // Alice encapsulates to Bob's public key
        Handshake.EncapsulationResult encapResult = Handshake.initiatorEncapsulate(kemPubB);
        byte[] ss = encapResult.sharedSecret;
        byte[] ct = encapResult.ciphertext;

        // Bob decapsulates
        byte[] ssBob = Handshake.responderDecapsulate(kemPrivB, ct);

        assertArrayEquals(ss, ssBob);

        // Derive initial keys
        byte[][] keysAlice = Kdf.deriveInitialKeys(ss);
        byte[] rkAlice = keysAlice[0];
        byte[] koAlice = keysAlice[1];

        byte[][] keysBob = Kdf.deriveInitialKeys(ssBob);
        byte[] rkBob = keysBob[0];
        byte[] koBob = keysBob[1];

        // Initialize chain keys
        byte[][] chainKeysAlice = Kdf.initChainKeys(rkAlice, koAlice);
        byte[] cksAlice = chainKeysAlice[0];
        byte[] ckrAlice = chainKeysAlice[1];

        byte[][] chainKeysBob = Kdf.initChainKeys(rkBob, koBob);
        byte[] cksBob = chainKeysBob[0];
        byte[] ckrBob = chainKeysBob[1];

        Session alice = new Session(
                1, rkAlice, koAlice, cksAlice, ckrAlice,
                kemPubA, kemPrivA, idPubA, idPrivA, idPubB, true);

        Session bob = new Session(
                1, rkBob, koBob, ckrBob, cksBob, // Swapped!
                kemPubB, kemPrivB, idPubB, idPrivB, idPubA, false);

        return new Object[] { alice, bob, ss };
    }

    @Test
    void testSendReceive() throws Exception {
        Object[] sessions = createTestSessions();
        Session alice = (Session) sessions[0];
        Session bob = (Session) sessions[1];

        byte[] plaintext = "Quantum-safe hello!".getBytes(StandardCharsets.UTF_8);
        Types.Message msg = alice.send(plaintext);
        byte[] decrypted = bob.receive(msg);

        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void testMultipleMessages() throws Exception {
        Object[] sessions = createTestSessions();
        Session alice = (Session) sessions[0];
        Session bob = (Session) sessions[1];

        for (int i = 0; i < 5; i++) {
            byte[] plaintext = ("Message " + i).getBytes(StandardCharsets.UTF_8);
            Types.Message msg = alice.send(plaintext);
            byte[] decrypted = bob.receive(msg);
            assertArrayEquals(plaintext, decrypted);
        }
    }

    @Test
    void testKoEnhancement() throws Exception {
        Object[] sessions = createTestSessions();
        Session alice = (Session) sessions[0];
        Session bob = (Session) sessions[1];
        byte[] ss = (byte[]) sessions[2];

        // Both sessions should start without Ko enhancement
        assertFalse(alice.isKoEnhanced());
        assertFalse(bob.isKoEnhanced());

        // Step 1: Both parties start enhancement and exchange commits
        Types.KoCommitMessage aliceCommit = alice.koStartEnhancement(ss);
        Types.KoCommitMessage bobCommit = bob.koStartEnhancement(ss);

        // Step 2: Process received commits and create reveals
        Types.KoRevealMessage aliceReveal = alice.koProcessCommit(bobCommit);
        Types.KoRevealMessage bobReveal = bob.koProcessCommit(aliceCommit);

        // Step 3: Finalize with received reveals
        alice.koFinalize(bobReveal);
        bob.koFinalize(aliceReveal);

        // Both sessions should now have enhanced Ko
        assertTrue(alice.isKoEnhanced());
        assertTrue(bob.isKoEnhanced());

        // Verify they can still communicate
        byte[] plaintext = "Post-enhancement message!".getBytes(StandardCharsets.UTF_8);
        Types.Message msg = alice.send(plaintext);
        byte[] decrypted = bob.receive(msg);
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void testRatchet() throws Exception {
        Object[] sessions = createTestSessions();
        Session alice = (Session) sessions[0];
        Session bob = (Session) sessions[1];

        // Send some messages first
        for (int i = 0; i < 3; i++) {
            byte[] plaintext = ("Pre-ratchet message " + i).getBytes(StandardCharsets.UTF_8);
            Types.Message msg = alice.send(plaintext);
            byte[] decrypted = bob.receive(msg);
            assertArrayEquals(plaintext, decrypted);
        }

        // Perform ratchet
        Types.RatchetMessage ratchetMsg = alice.initiateRatchet();
        Types.RatchetMessage response = bob.respondRatchet(ratchetMsg);
        alice.finalizeRatchet(response);

        assertEquals(1, alice.getEpoch());
        assertEquals(1, bob.getEpoch());

        // Send messages after ratchet
        byte[] plaintext = "Post-ratchet message!".getBytes(StandardCharsets.UTF_8);
        Types.Message msg = alice.send(plaintext);
        byte[] decrypted = bob.receive(msg);
        assertArrayEquals(plaintext, decrypted);
    }
}
