"""Dice52 Demo - Quantum-safe ratchet protocol demonstration."""

from .handshake import (
    generate_kem_keypair,
    generate_signing_keypair,
    initiator_encapsulate,
    responder_decapsulate,
)
from .kdf import derive_initial_keys, init_chain_keys
from .session import Session


def main():
    """Run the Dice52 demo."""
    print("=== Dice52 PQ Ratchet Demo (Python) ===\n")
    
    # Generate KEM key pairs for Alice and Bob
    print("Generating Kyber768 key pairs...")
    kem_pub_a, kem_priv_a = generate_kem_keypair()
    kem_pub_b, kem_priv_b = generate_kem_keypair()
    
    # Generate Dilithium identity key pairs
    print("Generating Dilithium3 identity keys...")
    id_pub_a, id_priv_a = generate_signing_keypair()
    id_pub_b, id_priv_b = generate_signing_keypair()
    
    # Alice encapsulates to Bob's public key
    print("\nAlice encapsulating to Bob's public key...")
    ss_alice, ct = initiator_encapsulate(kem_pub_b)
    
    # Bob decapsulates
    print("Bob decapsulating...")
    ss_bob = responder_decapsulate(kem_priv_b, ct)
    
    # Verify shared secrets match
    assert ss_alice == ss_bob, "Shared secrets should match!"
    print("✓ Shared secrets match!")
    
    # Derive initial keys
    print("\nDeriving initial keys...")
    rk_alice, ko_alice = derive_initial_keys(ss_alice)
    rk_bob, ko_bob = derive_initial_keys(ss_bob)
    
    # Initialize chain keys
    cks_alice, ckr_alice = init_chain_keys(rk_alice, ko_alice)
    cks_bob, ckr_bob = init_chain_keys(rk_bob, ko_bob)
    
    # Create sessions
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
    
    # Demonstrate ratcheting
    print("\n--- PQ Ratchet ---")
    print("Alice initiating ratchet...")
    ratchet_msg = alice.initiate_ratchet()
    print(f"  Public key size: {len(ratchet_msg.pub_key)} bytes")
    print(f"  Signature size: {len(ratchet_msg.sig)} bytes")
    
    print("Bob responding to ratchet...")
    response = bob.respond_ratchet(ratchet_msg)
    print(f"  Ciphertext size: {len(response.ct)} bytes")
    
    print("Alice finalizing ratchet...")
    alice.finalize_ratchet(response)
    
    print(f"✓ Ratchet complete! New epoch: {alice.epoch}")
    
    # Send message after ratchet
    print("\n--- Post-Ratchet Message ---")
    post_ratchet_msg = "This message uses new keys!"
    print(f"Alice sends: \"{post_ratchet_msg}\"")
    msg = alice.send(post_ratchet_msg.encode())
    decrypted = bob.receive(msg)
    print(f"Bob receives: \"{decrypted.decode('utf-8')}\"")
    
    print("\n=== Demo Complete ===")


if __name__ == "__main__":
    main()

