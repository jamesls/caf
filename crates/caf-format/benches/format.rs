//! Format microbenchmarks.
//!
//! These benchmarks are kept separate from the conformance tests:
//!
//! - SHAKE generation for the short first block and later 1 MiB blocks
//! - BLAKE2b-160 over 4 KiB, 1 MiB, and 1 GiB inputs
//! - Header encode and parse
//! - Hash-to-path and path-to-hash conversion
//!
//! Benchmarks measure release builds; fixture shapes and measurement rules
//! must remain stable so results stay comparable across runs.

#![expect(
    missing_docs,
    reason = "criterion_group! expands to an undocumented public function"
)]

use std::hint::black_box;

use caf_format::{
    ContentSeed, Digest, Hasher, Header, block_len, fill_block, hash_to_relpath,
    parse_hash_from_path,
};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};

const SEED: ContentSeed = ContentSeed::from_bytes(*b"benchmark-seed-!");
const PARENT_HEX: &str = "605cb937a87b5868c431a749863b38e708e09b76";
const GIB: u64 = 1 << 30;
const UPDATE_LEN: usize = 1 << 20;

fn shake_blocks(c: &mut Criterion) {
    let mut group = c.benchmark_group("shake");
    for index in [0, 1] {
        let len = block_len(index);
        let mut block = vec![0_u8; len];
        group.throughput(Throughput::Bytes(len as u64));
        group.bench_function(format!("block-{index}"), |b| {
            b.iter(|| {
                fill_block(SEED, index, &mut block);
                black_box(block.last().copied())
            });
        });
    }
    group.finish();
}

fn blake2b_160(c: &mut Criterion) {
    let mut group = c.benchmark_group("blake2b-160");

    // 4 KiB and 1 MiB: one-shot over a fixed buffer.
    for (label, len) in [("4KiB", 4096_usize), ("1MiB", 1 << 20)] {
        let data = vec![0xa5_u8; len];
        group.throughput(Throughput::Bytes(len as u64));
        group.bench_function(label, |b| {
            b.iter(|| black_box(Digest::compute(&data)));
        });
    }

    // 1 GiB: streamed through the hasher in 1 MiB updates, matching how
    // whole large files are digested; avoids a 1 GiB allocation.
    let update = vec![0xa5_u8; UPDATE_LEN];
    group.throughput(Throughput::Bytes(GIB));
    group.sample_size(10);
    group.bench_function("1GiB", |b| {
        b.iter(|| {
            let mut hasher = Hasher::new();
            for _ in 0..(GIB / UPDATE_LEN as u64) {
                hasher.update(&update);
            }
            black_box(hasher.finalize())
        });
    });
    group.finish();
}

fn header_codec(c: &mut Criterion) {
    let parent = Digest::from_hex(PARENT_HEX).expect("valid hex");
    let header = Header::new(parent, SEED, 4096).expect("legal file length");
    let encoded = header.encode();

    let mut group = c.benchmark_group("header");
    group.bench_function("encode", |b| {
        b.iter(|| black_box(header.encode()));
    });
    group.bench_function("parse", |b| {
        b.iter(|| Header::parse(black_box(&encoded)).expect("valid header"));
    });
    group.finish();
}

fn hash_paths(c: &mut Criterion) {
    let digest = Digest::from_hex(PARENT_HEX).expect("valid hex");
    let relpath = hash_to_relpath(digest);

    let mut group = c.benchmark_group("path");
    group.bench_function("hash-to-relpath", |b| {
        b.iter(|| black_box(hash_to_relpath(black_box(digest))));
    });
    group.bench_function("parse-hash-from-path", |b| {
        b.iter(|| parse_hash_from_path(black_box(&relpath)));
    });
    group.finish();
}

criterion_group!(benches, shake_blocks, blake2b_160, header_codec, hash_paths);
criterion_main!(benches);
