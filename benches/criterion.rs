use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use ghash::*;

const TEST_LENGTH: [usize; 7] = [
    0,
    512,
    1024,
    1024 * 2,
    1024 * 4,
    1024 * 8,
    1024 * 16,
];

fn small_message(c: &mut Criterion) {
    let mut group = c.benchmark_group("Small Message");
    for l in TEST_LENGTH.iter() {
        let message = vec![0; *l];
        group.throughput(Throughput::Bytes(*l as u64));
        group.bench_with_input(BenchmarkId::new("BLAKE-28", l), &message, |b, _| {
            b.iter(|| Blake28::hash_to_bytes(&message))
        });
        group.bench_with_input(BenchmarkId::new("BLAKE-32", l), &message, |b, _| {
            b.iter(|| Blake32::hash_to_bytes(&message))
        });
        group.bench_with_input(BenchmarkId::new("BLAKE-48", l), &message, |b, _| {
            b.iter(|| Blake48::hash_to_bytes(&message))
        });
        group.bench_with_input(BenchmarkId::new("BLAKE-64", l), &message, |b, _| {
            b.iter(|| Blake64::hash_to_bytes(&message))
        });
        group.bench_with_input(BenchmarkId::new("BLAKE-224", l), &message, |b, _| {
            b.iter(|| Blake224::hash_to_bytes(&message))
        });
        group.bench_with_input(BenchmarkId::new("BLAKE-256", l), &message, |b, _| {
            b.iter(|| Blake256::hash_to_bytes(&message))
        });
        group.bench_with_input(BenchmarkId::new("BLAKE-384", l), &message, |b, _| {
            b.iter(|| Blake384::hash_to_bytes(&message))
        });
        group.bench_with_input(BenchmarkId::new("BLAKE-512", l), &message, |b, _| {
            b.iter(|| Blake512::hash_to_bytes(&message))
        });
        group.bench_with_input(BenchmarkId::new("Keccak-224", l), &message, |b, _| {
            b.iter(|| Keccak224::hash_to_bytes(&message))
        });
        group.bench_with_input(BenchmarkId::new("Keccak-256", l), &message, |b, _| {
            b.iter(|| Keccak256::hash_to_bytes(&message))
        });
        group.bench_with_input(BenchmarkId::new("Keccak-384", l), &message, |b, _| {
            b.iter(|| Keccak384::hash_to_bytes(&message))
        });
        group.bench_with_input(BenchmarkId::new("Keccak-512", l), &message, |b, _| {
            b.iter(|| Keccak512::hash_to_bytes(&message))
        });
        group.bench_with_input(BenchmarkId::new("MD2", l), &message, |b, _| {
            b.iter(|| Md2::hash_to_bytes(&message))
        });
        group.bench_with_input(BenchmarkId::new("MD4", l), &message, |b, _| {
            b.iter(|| Md4::hash_to_bytes(&message))
        });
        group.bench_with_input(BenchmarkId::new("MD5", l), &message, |b, _| {
            b.iter(|| Md5::hash_to_bytes(&message))
        });
        group.bench_with_input(BenchmarkId::new("RIPEMD-128", l), &message, |b, _| {
            b.iter(|| Ripemd128::hash_to_bytes(&message))
        });
        group.bench_with_input(BenchmarkId::new("RIPEMD-160", l), &message, |b, _| {
            b.iter(|| Ripemd160::hash_to_bytes(&message))
        });
        group.bench_with_input(BenchmarkId::new("RIPEMD-256", l), &message, |b, _| {
            b.iter(|| Ripemd256::hash_to_bytes(&message))
        });
        group.bench_with_input(BenchmarkId::new("RIPEMD-320", l), &message, |b, _| {
            b.iter(|| Ripemd320::hash_to_bytes(&message))
        });
        group.bench_with_input(BenchmarkId::new("SHA-0", l), &message, |b, _| {
            b.iter(|| Sha0::hash_to_bytes(&message))
        });
        group.bench_with_input(BenchmarkId::new("SHA-1", l), &message, |b, _| {
            b.iter(|| Sha1::hash_to_bytes(&message))
        });
        group.bench_with_input(BenchmarkId::new("SHA-224", l), &message, |b, _| {
            b.iter(|| Sha224::hash_to_bytes(&message))
        });
        group.bench_with_input(BenchmarkId::new("SHA-256", l), &message, |b, _| {
            b.iter(|| Sha256::hash_to_bytes(&message))
        });
        group.bench_with_input(BenchmarkId::new("SHA-384", l), &message, |b, _| {
            b.iter(|| Sha384::hash_to_bytes(&message))
        });
        group.bench_with_input(BenchmarkId::new("SHA-512", l), &message, |b, _| {
            b.iter(|| Sha512::hash_to_bytes(&message))
        });
        group.bench_with_input(BenchmarkId::new("SHA-512/224", l), &message, |b, _| {
            b.iter(|| Sha512Trunc224::hash_to_bytes(&message))
        });
        group.bench_with_input(BenchmarkId::new("SHA-512/256", l), &message, |b, _| {
            b.iter(|| Sha512Trunc256::hash_to_bytes(&message))
        });
        group.bench_with_input(BenchmarkId::new("SHA3-224", l), &message, |b, _| {
            b.iter(|| Sha3_224::hash_to_bytes(&message))
        });
        group.bench_with_input(BenchmarkId::new("SHA3-256", l), &message, |b, _| {
            b.iter(|| Sha3_256::hash_to_bytes(&message))
        });
        group.bench_with_input(BenchmarkId::new("SHA3-384", l), &message, |b, _| {
            b.iter(|| Sha3_384::hash_to_bytes(&message))
        });
        group.bench_with_input(BenchmarkId::new("SHA3-512", l), &message, |b, _| {
            b.iter(|| Sha3_512::hash_to_bytes(&message))
        });
    }
    group.finish();
}

criterion_group!(benches, small_message);
criterion_main!(benches);
