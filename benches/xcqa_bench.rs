use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use xcqa::{Dictionary, keygen, encrypt, decrypt};

fn bench_dictionary_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("XCQA Dictionary Generation");

    group.bench_function("default_config", |b| {
        b.iter(|| {
            Dictionary::generate()
        });
    });

    group.finish();
}

fn bench_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("XCQA KeyGen");

    group.bench_function("keygen", |b| {
        b.iter(|| {
            keygen()
        });
    });

    group.finish();
}

fn bench_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("XCQA Encrypt");

    // Pre-generate keys
    let (pk, _sk) = keygen();

    for msg_len in [16, 64, 256, 1024].iter() {
        let message = vec![0x42u8; *msg_len];
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}bytes", msg_len)),
            &message,
            |b, msg| {
                b.iter(|| {
                    encrypt(black_box(msg), black_box(&pk))
                });
            },
        );
    }

    group.finish();
}

fn bench_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("XCQA Decrypt");

    // Pre-generate keys and ciphertext
    let (pk, sk) = keygen();

    for msg_len in [16, 64, 256, 1024].iter() {
        let message = vec![0x42u8; *msg_len];
        let ciphertext = encrypt(&message, &pk);

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}bytes", msg_len)),
            &ciphertext,
            |b, ct| {
                b.iter(|| {
                    decrypt(black_box(ct), black_box(&sk))
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_dictionary_generation, bench_keygen, bench_encrypt, bench_decrypt);
criterion_main!(benches);
