"""Dice52 Demo - Quantum-safe ratchet protocol demonstration with hybrid KEM."""

from .handshake import (
    generate_kem_keypair,
    generate_signing_keypair,
    generate_x25519_keypair,
    initiator_hybrid_encapsulate,
    responder_hybrid_decapsulate,
)
from .kdf import derive_initial_keys, init_chain_keys
from .session import Session


def main():
    """Run the Dice52 demo with hybrid KEM."""
    print("=== Dice52 PQ Ratchet Demo (Python) ===\n")
    
    # Generate Kyber KEM key pairs for Alice and Bob
    print("Generating Kyber768 key pairs...")
    kem_pub_a, kem_priv_a = generate_kem_keypair()
    kem_pub_b, kem_priv_b = generate_kem_keypair()
    
    # Generate X25519 key pairs for hybrid KEM
    print("Generating X25519 key pairs...")
    ecdh_pub_a, ecdh_priv_a = generate_x25519_keypair()
    ecdh_pub_b, ecdh_priv_b = generate_x25519_keypair()
    
    # Generate Dilithium identity key pairs
    print("Generating Dilithium3 identity keys...")
    id_pub_a, id_priv_a = generate_signing_keypair()
    id_pub_b, id_priv_b = generate_signing_keypair()
    
    # Alice performs hybrid encapsulation to Bob's public keys (Kyber + X25519)
    print("\nAlice performing hybrid encapsulation to Bob's public keys...")
    ss_alice, kyber_ct, alice_ecdh_pub, alice_ecdh_priv = initiator_hybrid_encapsulate(kem_pub_b, ecdh_pub_b)
    
    # Bob performs hybrid decapsulation
    print("Bob performing hybrid decapsulation...")
    ss_bob = responder_hybrid_decapsulate(kem_priv_b, ecdh_priv_b, kyber_ct, alice_ecdh_pub)
    
    # Verify shared secrets match
    assert ss_alice == ss_bob, "Hybrid shared secrets should match!"
    print("✓ Hybrid shared secrets match!")
    
    # Derive initial keys
    print("\nDeriving initial keys...")
    rk_alice, ko_alice = derive_initial_keys(ss_alice)
    rk_bob, ko_bob = derive_initial_keys(ss_bob)
    
    # Initialize chain keys
    cks_alice, ckr_alice = init_chain_keys(rk_alice, ko_alice)
    cks_bob, ckr_bob = init_chain_keys(rk_bob, ko_bob)
    
    # Create sessions with X25519 keys for future hybrid ratchets
    alice = Session(
        session_id=1,
        rk=rk_alice,
        ko=ko_alice,
        cks=cks_alice,
        ckr=ckr_alice,
        kem_pub=kem_pub_a,
        kem_priv=kem_priv_a,
        id_pub=id_pub_a,
        id_priv=id_priv_a,
        peer_id=id_pub_b,
        is_initiator=True,
        ecdh_pub=ecdh_pub_a,
        ecdh_priv=ecdh_priv_a,
        peer_ecdh_pub=ecdh_pub_b,
    )
    
    # Bob's send = Alice's receive, Bob's receive = Alice's send
    bob = Session(
        session_id=1,
        rk=rk_bob,
        ko=ko_bob,
        cks=ckr_bob,  # Bob's send = Alice's receive
        ckr=cks_bob,  # Bob's receive = Alice's send
        kem_pub=kem_pub_b,
        kem_priv=kem_priv_b,
        id_pub=id_pub_b,
        id_priv=id_priv_b,
        peer_id=id_pub_a,
        is_initiator=False,
        ecdh_pub=ecdh_pub_b,
        ecdh_priv=ecdh_priv_b,
        peer_ecdh_pub=ecdh_pub_a,
    )
    
    # Exchange messages
    print("\n--- Message Exchange ---")
    
    messages = [
        "Hello Bob! This is quantum-safe.",
        "Ready for the post-quantum era?",
        "Harvest now, decrypt never!",
    ]
    
    for i, plaintext in enumerate(messages):
        print(f"\nAlice sends: \"{plaintext}\"")
        msg = alice.send(plaintext.encode())
        print(f"  Encrypted header: {msg.header[:40]}...")
        print(f"  Encrypted body: {msg.body[:40]}...")
        
        decrypted = bob.receive(msg)
        decrypted_str = decrypted.decode('utf-8')
        print(f"Bob receives: \"{decrypted_str}\"")
        
        assert plaintext.encode() == decrypted, f"Message {i} mismatch!"
    
    print("\n✓ All messages exchanged successfully!")
    
    # Demonstrate hybrid ratcheting
    print("\n--- Hybrid PQ Ratchet ---")
    print("Alice initiating hybrid ratchet...")
    ratchet_msg = alice.initiate_ratchet()
    print(f"  Kyber public key size: {len(ratchet_msg.pub_key)} bytes")
    if ratchet_msg.ecdh_pub:
        print(f"  X25519 public key size: {len(ratchet_msg.ecdh_pub)} bytes")
    print(f"  Signature size: {len(ratchet_msg.sig)} bytes")
    
    print("Bob responding to hybrid ratchet...")
    response = bob.respond_ratchet(ratchet_msg)
    print(f"  Kyber ciphertext size: {len(response.ct)} bytes")
    
    print("Alice finalizing hybrid ratchet...")
    alice.finalize_ratchet(response)
    
    print(f"✓ Hybrid ratchet complete! New epoch: {alice.epoch}")
    
    # Send message after ratchet
    print("\n--- Post-Ratchet Message ---")
    post_ratchet_msg = "This message uses new hybrid keys!"
    print(f"Alice sends: \"{post_ratchet_msg}\"")
    msg = alice.send(post_ratchet_msg.encode())
    decrypted = bob.receive(msg)
    print(f"Bob receives: \"{decrypted.decode('utf-8')}\"")
    
    print("\n=== Demo Complete ===")


if __name__ == "__main__":
    main()
