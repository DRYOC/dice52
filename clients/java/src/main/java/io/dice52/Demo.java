package io.dice52;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.crypto.crystals.dilithium.*;
import org.bouncycastle.pqc.crypto.crystals.kyber.*;

import java.nio.charset.StandardCharsets;
import java.security.Security;

/**
 * Dice52 Demo - Quantum-safe ratchet protocol demonstration with hybrid KEM.
 */
public class Demo {

    public static void main(String[] args) throws Exception {
        // Register Bouncy Castle provider
        Security.addProvider(new BouncyCastleProvider());

        System.out.println("=== Dice52 PQ Ratchet Demo (Java) ===\n");

        // Generate Kyber KEM key pairs for Alice and Bob
        System.out.println("Generating Kyber768 key pairs...");
        AsymmetricCipherKeyPair kemKeysA = Handshake.generateKemKeypair();
        KyberPublicKeyParameters kemPubA = (KyberPublicKeyParameters) kemKeysA.getPublic();
        KyberPrivateKeyParameters kemPrivA = (KyberPrivateKeyParameters) kemKeysA.getPrivate();

        AsymmetricCipherKeyPair kemKeysB = Handshake.generateKemKeypair();
        KyberPublicKeyParameters kemPubB = (KyberPublicKeyParameters) kemKeysB.getPublic();
        KyberPrivateKeyParameters kemPrivB = (KyberPrivateKeyParameters) kemKeysB.getPrivate();

        // Generate X25519 key pairs for hybrid KEM
        System.out.println("Generating X25519 key pairs...");
        AsymmetricCipherKeyPair ecdhKeysA = Handshake.generateX25519Keypair();
        X25519PublicKeyParameters ecdhPubA = (X25519PublicKeyParameters) ecdhKeysA.getPublic();
        X25519PrivateKeyParameters ecdhPrivA = (X25519PrivateKeyParameters) ecdhKeysA.getPrivate();

        AsymmetricCipherKeyPair ecdhKeysB = Handshake.generateX25519Keypair();
        X25519PublicKeyParameters ecdhPubB = (X25519PublicKeyParameters) ecdhKeysB.getPublic();
        X25519PrivateKeyParameters ecdhPrivB = (X25519PrivateKeyParameters) ecdhKeysB.getPrivate();

        // Generate Dilithium identity key pairs
        System.out.println("Generating Dilithium3 identity keys...");
        AsymmetricCipherKeyPair idKeysA = Handshake.generateSigningKeypair();
        DilithiumPublicKeyParameters idPubA = (DilithiumPublicKeyParameters) idKeysA.getPublic();
        DilithiumPrivateKeyParameters idPrivA = (DilithiumPrivateKeyParameters) idKeysA.getPrivate();

        AsymmetricCipherKeyPair idKeysB = Handshake.generateSigningKeypair();
        DilithiumPublicKeyParameters idPubB = (DilithiumPublicKeyParameters) idKeysB.getPublic();
        DilithiumPrivateKeyParameters idPrivB = (DilithiumPrivateKeyParameters) idKeysB.getPrivate();

        // Alice performs hybrid encapsulation to Bob's public keys (Kyber + X25519)
        System.out.println("\nAlice performing hybrid encapsulation to Bob's public keys...");
        Handshake.HybridEncapsulationResult hybridResult = Handshake.initiatorHybridEncapsulate(kemPubB, ecdhPubB);
        byte[] ssAlice = hybridResult.hybridSharedSecret;

        // Bob performs hybrid decapsulation
        System.out.println("Bob performing hybrid decapsulation...");
        X25519PublicKeyParameters aliceEcdhPub = new X25519PublicKeyParameters(hybridResult.ecdhPub, 0);
        byte[] ssBob = Handshake.responderHybridDecapsulate(kemPrivB, ecdhPrivB, hybridResult.kyberCiphertext,
                hybridResult.ecdhPub);

        // Verify shared secrets match
        if (!java.util.Arrays.equals(ssAlice, ssBob)) {
            throw new RuntimeException("Hybrid shared secrets don't match!");
        }
        System.out.println("✓ Hybrid shared secrets match!");

        // Derive initial keys
        System.out.println("\nDeriving initial keys...");
        byte[][] keysAlice = Kdf.deriveInitialKeys(ssAlice);
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

        // Create sessions with X25519 keys for future hybrid ratchets
        Session alice = new Session(
                1,
                rkAlice,
                koAlice,
                cksAlice,
                ckrAlice,
                kemPubA,
                kemPrivA,
                ecdhPubA,
                ecdhPrivA,
                ecdhPubB,
                idPubA,
                idPrivA,
                idPubB,
                true // Alice is initiator
        );

        // Bob's send = Alice's receive, Bob's receive = Alice's send
        Session bob = new Session(
                1,
                rkBob,
                koBob,
                ckrBob, // Bob's send = Alice's receive
                cksBob, // Bob's receive = Alice's send
                kemPubB,
                kemPrivB,
                ecdhPubB,
                ecdhPrivB,
                ecdhPubA,
                idPubB,
                idPrivB,
                idPubA,
                false // Bob is responder
        );

        // Exchange messages
        System.out.println("\n--- Message Exchange ---");

        String[] messages = {
                "Hello Bob! This is quantum-safe.",
                "Ready for the post-quantum era?",
                "Harvest now, decrypt never!"
        };

        for (int i = 0; i < messages.length; i++) {
            String plaintext = messages[i];
            System.out.println("\nAlice sends: \"" + plaintext + "\"");

            Types.Message msg = alice.send(plaintext.getBytes(StandardCharsets.UTF_8));
            System.out.println("  Encrypted header: " +
                    msg.header.substring(0, Math.min(40, msg.header.length())) + "...");
            System.out.println("  Encrypted body: " +
                    msg.body.substring(0, Math.min(40, msg.body.length())) + "...");

            byte[] decrypted = bob.receive(msg);
            String decryptedStr = new String(decrypted, StandardCharsets.UTF_8);
            System.out.println("Bob receives: \"" + decryptedStr + "\"");

            if (!plaintext.equals(decryptedStr)) {
                throw new RuntimeException("Message " + i + " mismatch!");
            }
        }

        System.out.println("\n✓ All messages exchanged successfully!");

        // Demonstrate hybrid ratcheting
        System.out.println("\n--- Hybrid PQ Ratchet ---");
        System.out.println("Alice initiating hybrid ratchet...");
        Types.RatchetMessage ratchetMsg = alice.initiateRatchet();
        System.out.println("  Kyber public key size: " + ratchetMsg.pubKey.length + " bytes");
        if (ratchetMsg.ecdhPub != null) {
            System.out.println("  X25519 public key size: " + ratchetMsg.ecdhPub.length + " bytes");
        }
        System.out.println("  Signature size: " + ratchetMsg.sig.length + " bytes");

        System.out.println("Bob responding to hybrid ratchet...");
        Types.RatchetMessage response = bob.respondRatchet(ratchetMsg);
        System.out.println("  Kyber ciphertext size: " + response.ct.length + " bytes");

        System.out.println("Alice finalizing hybrid ratchet...");
        alice.finalizeRatchet(response);

        System.out.println("✓ Hybrid ratchet complete! New epoch: " + alice.getEpoch());

        // Send message after ratchet
        System.out.println("\n--- Post-Ratchet Message ---");
        String postRatchetMsg = "This message uses new hybrid keys!";
        System.out.println("Alice sends: \"" + postRatchetMsg + "\"");
        Types.Message msg = alice.send(postRatchetMsg.getBytes(StandardCharsets.UTF_8));
        byte[] decrypted = bob.receive(msg);
        System.out.println("Bob receives: \"" + new String(decrypted, StandardCharsets.UTF_8) + "\"");

        System.out.println("\n=== Demo Complete ===");
    }
}
