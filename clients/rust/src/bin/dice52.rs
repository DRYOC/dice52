//! Dice52 Demo - Quantum-safe ratchet protocol demonstration with hybrid KEM

use dice52::{
    derive_initial_keys, generate_kem_keypair, generate_signing_keypair, generate_x25519_keypair,
    init_chain_keys, initiator_hybrid_encapsulate, responder_hybrid_decapsulate, Session,
};

fn main() {
    println!("=== Dice52 PQ Ratchet Demo ===\n");

    // Generate Kyber KEM key pairs for Alice and Bob
    println!("Generating Kyber768 key pairs...");
    let (kem_pub_a, kem_priv_a) = generate_kem_keypair();
    let (kem_pub_b, kem_priv_b) = generate_kem_keypair();

    // Generate X25519 key pairs for hybrid KEM
    println!("Generating X25519 key pairs...");
    let (ecdh_pub_a, ecdh_priv_a) = generate_x25519_keypair();
    let (ecdh_pub_b, ecdh_priv_b) = generate_x25519_keypair();

    // Generate Dilithium identity key pairs
    println!("Generating Dilithium3 identity keys...");
    let (id_pub_a, id_priv_a) = generate_signing_keypair();
    let (id_pub_b, id_priv_b) = generate_signing_keypair();

    // Alice performs hybrid encapsulation to Bob's public keys (Kyber + X25519)
    println!("\nAlice performing hybrid encapsulation to Bob's public keys...");
    let result =
        initiator_hybrid_encapsulate(&kem_pub_b, &ecdh_pub_b).expect("Hybrid encapsulation failed");

    // Bob performs hybrid decapsulation
    println!("Bob performing hybrid decapsulation...");
    let ss_bob = responder_hybrid_decapsulate(
        &kem_priv_b,
        &ecdh_priv_b,
        &result.kyber_ct,
        &result.ecdh_pub,
    )
    .expect("Hybrid decapsulation failed");

    // Verify shared secrets match
    let ss_alice = result.ss_hybrid.clone();
    assert_eq!(ss_alice, ss_bob, "Hybrid shared secrets should match!");
    println!("✓ Hybrid shared secrets match!");

    // Derive initial keys
    println!("\nDeriving initial keys...");
    let (rk_alice, ko_alice) = derive_initial_keys(&ss_alice);
    let (rk_bob, ko_bob) = derive_initial_keys(&ss_bob);

    // Initialize chain keys
    let (cks_alice, ckr_alice) = init_chain_keys(&rk_alice, &ko_alice);
    let (cks_bob, ckr_bob) = init_chain_keys(&rk_bob, &ko_bob);

    // Create sessions with X25519 keys for future hybrid ratchets
    let alice = Session::new_with_ecdh(
        1,
        rk_alice,
        ko_alice,
        cks_alice,
        ckr_alice,
        kem_pub_a,
        kem_priv_a,
        ecdh_pub_a.clone(),
        ecdh_priv_a,
        ecdh_pub_b.clone(),
        id_pub_a.clone(),
        id_priv_a,
        id_pub_b.clone(),
        true, // Alice is initiator
    );

    // Bob's send = Alice's receive, Bob's receive = Alice's send
    let bob = Session::new_with_ecdh(
        1,
        rk_bob,
        ko_bob,
        ckr_bob, // Bob's send = Alice's receive
        cks_bob, // Bob's receive = Alice's send
        kem_pub_b,
        kem_priv_b,
        ecdh_pub_b.clone(),
        ecdh_priv_b,
        ecdh_pub_a,
        id_pub_b,
        id_priv_b,
        id_pub_a,
        false, // Bob is responder
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

    // Demonstrate hybrid ratcheting
    println!("\n--- Hybrid PQ Ratchet ---");
    println!("Alice initiating hybrid ratchet...");
    let ratchet_msg = alice.initiate_ratchet().expect("Ratchet initiation failed");
    println!(
        "  Kyber public key size: {} bytes",
        ratchet_msg.pub_key.as_ref().unwrap().len()
    );
    if let Some(ecdh_pub) = &ratchet_msg.ecdh_pub {
        println!("  X25519 public key size: {} bytes", ecdh_pub.len());
    }
    println!(
        "  Signature size: {} bytes",
        ratchet_msg.sig.as_ref().unwrap().len()
    );

    println!("Bob responding to hybrid ratchet...");
    let response = bob
        .respond_ratchet(&ratchet_msg)
        .expect("Ratchet response failed");
    println!(
        "  Kyber ciphertext size: {} bytes",
        response.ct.as_ref().unwrap().len()
    );

    println!("Alice finalizing hybrid ratchet...");
    alice
        .finalize_ratchet(&response)
        .expect("Ratchet finalization failed");

    println!("✓ Hybrid ratchet complete! New epoch: {}", alice.epoch());

    // Send message after ratchet
    println!("\n--- Post-Ratchet Message ---");
    let post_ratchet_msg = "This message uses new hybrid keys!";
    println!("Alice sends: \"{}\"", post_ratchet_msg);
    let msg = alice
        .send(post_ratchet_msg.as_bytes())
        .expect("Send failed");
    let decrypted = bob.receive(&msg).expect("Receive failed");
    println!("Bob receives: \"{}\"", String::from_utf8_lossy(&decrypted));

    println!("\n=== Demo Complete ===");
}
