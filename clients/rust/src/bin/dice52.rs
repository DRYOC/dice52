//! Dice52 Demo - Quantum-safe ratchet protocol demonstration

use dice52::{
    derive_initial_keys, init_chain_keys, initiator_encapsulate, responder_decapsulate, Session,
};
use pqcrypto_dilithium::dilithium3;
use pqcrypto_kyber::kyber768;

fn main() {
    println!("=== Dice52 PQ Ratchet Demo ===\n");

    // Generate KEM key pairs for Alice and Bob
    println!("Generating Kyber768 key pairs...");
    let (kem_pub_a, kem_priv_a) = kyber768::keypair();
    let (kem_pub_b, kem_priv_b) = kyber768::keypair();

    // Generate Dilithium identity key pairs
    println!("Generating Dilithium3 identity keys...");
    let (id_pub_a, id_priv_a) = dilithium3::keypair();
    let (id_pub_b, id_priv_b) = dilithium3::keypair();

    // Alice encapsulates to Bob's public key
    println!("\nAlice encapsulating to Bob's public key...");
    let (ss_alice, ct) = initiator_encapsulate(&kem_pub_b);

    // Bob decapsulates
    println!("Bob decapsulating...");
    let ss_bob = responder_decapsulate(&kem_priv_b, &ct).expect("Decapsulation failed");

    // Verify shared secrets match
    assert_eq!(ss_alice, ss_bob, "Shared secrets should match!");
    println!("✓ Shared secrets match!");

    // Derive initial keys
    println!("\nDeriving initial keys...");
    let (rk_alice, ko_alice) = derive_initial_keys(&ss_alice);
    let (rk_bob, ko_bob) = derive_initial_keys(&ss_bob);

    // Initialize chain keys
    let (cks_alice, ckr_alice) = init_chain_keys(&rk_alice, &ko_alice);
    let (cks_bob, ckr_bob) = init_chain_keys(&rk_bob, &ko_bob);

    // Create sessions
    let alice = Session::new(
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
    );

    // Bob's send = Alice's receive, Bob's receive = Alice's send
    let bob = Session::new(
        1, rk_bob, ko_bob, ckr_bob, // Bob's send = Alice's receive
        cks_bob, // Bob's receive = Alice's send
        kem_pub_b, kem_priv_b, id_pub_b, id_priv_b, id_pub_a,
    );

    // Exchange messages
    println!("\n--- Message Exchange ---");

    let messages = [
        "Hello Bob! This is quantum-safe.",
        "Ready for the post-quantum era?",
        "Harvest now, decrypt never!",
    ];

    for (i, plaintext) in messages.iter().enumerate() {
        println!("\nAlice sends: \"{}\"", plaintext);
        let msg = alice.send(plaintext.as_bytes()).expect("Send failed");
        println!(
            "  Encrypted header: {}...",
            &msg.header[..40.min(msg.header.len())]
        );
        println!(
            "  Encrypted body: {}...",
            &msg.body[..40.min(msg.body.len())]
        );

        let decrypted = bob.receive(&msg).expect("Receive failed");
        let decrypted_str = String::from_utf8_lossy(&decrypted);
        println!("Bob receives: \"{}\"", decrypted_str);

        assert_eq!(
            plaintext.as_bytes(),
            &decrypted[..],
            "Message {} mismatch!",
            i
        );
    }

    println!("\n✓ All messages exchanged successfully!");

    // Demonstrate ratcheting
    println!("\n--- PQ Ratchet ---");
    println!("Alice initiating ratchet...");
    let ratchet_msg = alice.initiate_ratchet().expect("Ratchet initiation failed");
    println!(
        "  Public key size: {} bytes",
        ratchet_msg.pub_key.as_ref().unwrap().len()
    );
    println!(
        "  Signature size: {} bytes",
        ratchet_msg.sig.as_ref().unwrap().len()
    );

    println!("Bob responding to ratchet...");
    let response = bob
        .respond_ratchet(&ratchet_msg)
        .expect("Ratchet response failed");
    println!(
        "  Ciphertext size: {} bytes",
        response.ct.as_ref().unwrap().len()
    );

    println!("Alice finalizing ratchet...");
    alice
        .finalize_ratchet(&response)
        .expect("Ratchet finalization failed");

    println!("✓ Ratchet complete! New epoch: {}", alice.epoch());

    // Send message after ratchet
    println!("\n--- Post-Ratchet Message ---");
    let post_ratchet_msg = "This message uses new keys!";
    println!("Alice sends: \"{}\"", post_ratchet_msg);
    let msg = alice
        .send(post_ratchet_msg.as_bytes())
        .expect("Send failed");
    let decrypted = bob.receive(&msg).expect("Receive failed");
    println!("Bob receives: \"{}\"", String::from_utf8_lossy(&decrypted));

    println!("\n=== Demo Complete ===");
}
