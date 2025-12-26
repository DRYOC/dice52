"""Tests for Dice52 session functionality."""

import pytest
from dice52 import (
    Session,
    generate_kem_keypair,
    generate_signing_keypair,
    initiator_encapsulate,
    responder_decapsulate,
    derive_initial_keys,
    init_chain_keys,
)


def create_test_sessions():
    """Create a pair of test sessions."""
    # Generate KEM key pairs
    kem_pub_a, kem_priv_a = generate_kem_keypair()
    kem_pub_b, kem_priv_b = generate_kem_keypair()
    
    # Generate identity key pairs
    id_pub_a, id_priv_a = generate_signing_keypair()
    id_pub_b, id_priv_b = generate_signing_keypair()
    
    # Alice encapsulates to Bob's public key
    ss, ct = initiator_encapsulate(kem_pub_b)
    
    # Bob decapsulates
    ss_bob = responder_decapsulate(kem_priv_b, ct)
    
    assert ss == ss_bob
    
    # Derive initial keys
    rk_alice, ko_alice = derive_initial_keys(ss)
    rk_bob, ko_bob = derive_initial_keys(ss_bob)
    
    # Initialize chain keys
    cks_alice, ckr_alice = init_chain_keys(rk_alice, ko_alice)
    cks_bob, ckr_bob = init_chain_keys(rk_bob, ko_bob)
    
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
    
    return alice, bob, ss


def test_send_receive():
    """Test basic send/receive."""
    alice, bob, _ss = create_test_sessions()
    
    plaintext = b"Quantum-safe hello!"
    msg = alice.send(plaintext)
    decrypted = bob.receive(msg)
    
    assert decrypted == plaintext


def test_multiple_messages():
    """Test multiple messages."""
    alice, bob, _ss = create_test_sessions()
    
    for i in range(5):
        plaintext = f"Message {i}".encode()
        msg = alice.send(plaintext)
        decrypted = bob.receive(msg)
        assert decrypted == plaintext


def test_ko_enhancement():
    """Test Ko enhancement protocol."""
    alice, bob, ss = create_test_sessions()
    
    # Both sessions should start without Ko enhancement
    assert not alice.is_ko_enhanced()
    assert not bob.is_ko_enhanced()
    
    # Step 1: Both parties start enhancement and exchange commits
    alice_commit = alice.ko_start_enhancement(ss)
    bob_commit = bob.ko_start_enhancement(ss)
    
    # Step 2: Process received commits and create reveals
    alice_reveal = alice.ko_process_commit(bob_commit)
    bob_reveal = bob.ko_process_commit(alice_commit)
    
    # Step 3: Finalize with received reveals
    alice.ko_finalize(bob_reveal)
    bob.ko_finalize(alice_reveal)
    
    # Both sessions should now have enhanced Ko
    assert alice.is_ko_enhanced()
    assert bob.is_ko_enhanced()
    
    # Verify they can still communicate
    plaintext = b"Post-enhancement message!"
    msg = alice.send(plaintext)
    decrypted = bob.receive(msg)
    assert decrypted == plaintext


def test_ratchet():
    """Test PQ ratchet."""
    alice, bob, _ss = create_test_sessions()
    
    # Send some messages first
    for i in range(3):
        plaintext = f"Pre-ratchet message {i}".encode()
        msg = alice.send(plaintext)
        decrypted = bob.receive(msg)
        assert decrypted == plaintext
    
    # Perform ratchet
    ratchet_msg = alice.initiate_ratchet()
    response = bob.respond_ratchet(ratchet_msg)
    alice.finalize_ratchet(response)
    
    assert alice.epoch == 1
    assert bob.epoch == 1
    
    # Send messages after ratchet
    plaintext = b"Post-ratchet message!"
    msg = alice.send(plaintext)
    decrypted = bob.receive(msg)
    assert decrypted == plaintext


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

