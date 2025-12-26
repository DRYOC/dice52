# Dice52-PQ Python Implementation

A Python 3 implementation of the Dice52-PQ post-quantum ratcheting protocol.

## Requirements

- Python 3.9+
- kyber-py (pure Python ML-KEM/Kyber implementation)
- dilithium-py (pure Python ML-DSA/Dilithium implementation)
- pycryptodome (for ChaCha20-Poly1305, HKDF, SHA-256)

## Installation

```bash
# Create virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install -e .
```

Or using the Makefile:

```bash
make install
```

## Usage

### Demo

```bash
python -m dice52.demo
# or
make demo
```

### Library Usage

```python
from dice52 import (
    Session,
    generate_kem_keypair,
    generate_signing_keypair,
    initiator_encapsulate,
    responder_decapsulate,
    derive_initial_keys,
    init_chain_keys,
)

# Generate key pairs
kem_pub_a, kem_priv_a = generate_kem_keypair()
kem_pub_b, kem_priv_b = generate_kem_keypair()
id_pub_a, id_priv_a = generate_signing_keypair()
id_pub_b, id_priv_b = generate_signing_keypair()

# Key exchange
ss_alice, ct = initiator_encapsulate(kem_pub_b)
ss_bob = responder_decapsulate(kem_priv_b, ct)

# Derive session keys
rk_alice, ko_alice = derive_initial_keys(ss_alice)
cks_alice, ckr_alice = init_chain_keys(rk_alice, ko_alice)

rk_bob, ko_bob = derive_initial_keys(ss_bob)
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

bob = Session(
    session_id=1,
    rk=rk_bob,
    ko=ko_bob,
    cks=ckr_bob,  # Swapped!
    ckr=cks_bob,  # Swapped!
    kem_pub=kem_pub_b,
    kem_priv=kem_priv_b,
    id_pub=id_pub_b,
    id_priv=id_priv_b,
    peer_id=id_pub_a,
    is_initiator=False,
)

# Send messages
msg = alice.send(b"Hello, quantum-safe world!")
plaintext = bob.receive(msg)
print(plaintext.decode())  # "Hello, quantum-safe world!"
```

## Testing

```bash
make test
```

## Warning

This is an experimental protocol implementation. Do NOT use in production systems.
