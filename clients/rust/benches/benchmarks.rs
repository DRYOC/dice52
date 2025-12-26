//! Benchmarks for Dice52 operations

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dice52::{derive_initial_keys, init_chain_keys, initiator_encapsulate, responder_decapsulate};
use pqcrypto_kyber::kyber768;

fn bench_kem_operations(c: &mut Criterion) {
    let (pub_key, priv_key) = kyber768::keypair();

    c.bench_function("kyber768_encapsulate", |b| {
        b.iter(|| initiator_encapsulate(black_box(&pub_key)))
    });

    let (_, ct) = initiator_encapsulate(&pub_key);
    c.bench_function("kyber768_decapsulate", |b| {
        b.iter(|| responder_decapsulate(black_box(&priv_key), black_box(&ct)))
    });
}

fn bench_kdf_operations(c: &mut Criterion) {
    let ss = vec![0u8; 32];

    c.bench_function("derive_initial_keys", |b| {
        b.iter(|| derive_initial_keys(black_box(&ss)))
    });

    let (rk, ko) = derive_initial_keys(&ss);
    c.bench_function("init_chain_keys", |b| {
        b.iter(|| init_chain_keys(black_box(&rk), black_box(&ko)))
    });
}

criterion_group!(benches, bench_kem_operations, bench_kdf_operations);
criterion_main!(benches);
