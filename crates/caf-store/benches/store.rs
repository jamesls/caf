//! End-to-end store benchmarks.
//!
//! The benchmarks measure generation, size selection, serial verification,
//! and parallel verification. Fixture shapes and measurement rules remain
//! stable so results stay comparable:
//!
//! - `gen/1000x4KiB`: per-file and directory overhead (files/s).
//! - `gen/8x8MiB`: sequential generation byte throughput.
//! - `size/*`: size-spec parsing and distribution sampling.
//! - `verify/1000x4KiB`: clean small-file verification (files/s); the
//!   full-scale numbers come from `examples/verify.rs`.
//! - `verify/1000x4KiB-jobsN`: the parallel pipeline over the
//!   same store at several worker counts.
//! - `verify/8x8MiB`: clean sequential verification byte throughput.
//! - `verify/8x8MiB-jobsN` — parallel byte throughput (one worker per
//!   file at most; the store has eight files).
//! - `verify/corrupt-8MiB` — the corruption-analysis path (SHAKE
//!   regeneration plus chunk comparison at the default 4,096-byte
//!   analysis chunk size).
//!
//! Each generation iteration writes into a fresh temporary store on the
//! same filesystem; teardown happens outside the timed section.
//! Verification benchmarks reuse one prebuilt store per benchmark
//! because verifying never modifies it.

#![expect(
    missing_docs,
    reason = "criterion_group! expands to an undocumented public function"
)]

use std::hint::black_box;
use std::io::{Seek as _, SeekFrom, Write as _};
use std::num::NonZeroUsize;

use caf_store::{Generator, SizeChooser, SizeSpec, Verifier};
use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};

fn generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("gen");
    group.sample_size(10);

    group.throughput(Throughput::Elements(1000));
    group.bench_function("1000x4KiB", |b| {
        b.iter_batched(
            || tempfile::tempdir().expect("create temp store"),
            |store| {
                let report = Generator::builder(store.path())
                    .max_files(1000)
                    .file_sizes(SizeChooser::fixed(4096))
                    .build()
                    .generate()
                    .expect("generation succeeds");
                assert_eq!(report.files_created(), 1000);
                store
            },
            BatchSize::PerIteration,
        );
    });

    group.throughput(Throughput::Bytes(8 * 8 * 1024 * 1024));
    group.bench_function("8x8MiB", |b| {
        b.iter_batched(
            || tempfile::tempdir().expect("create temp store"),
            |store| {
                let report = Generator::builder(store.path())
                    .max_files(8)
                    .file_sizes(SizeChooser::fixed(8 * 1024 * 1024))
                    .build()
                    .generate()
                    .expect("generation succeeds");
                assert_eq!(report.files_created(), 8);
                store
            },
            BatchSize::PerIteration,
        );
    });

    group.finish();
}

fn verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify");
    group.sample_size(10);

    let small = tempfile::tempdir().expect("create temp store");
    Generator::builder(small.path())
        .max_files(1000)
        .file_sizes(SizeChooser::fixed(4096))
        .build()
        .generate()
        .expect("generation succeeds");
    group.throughput(Throughput::Elements(1000));
    group.bench_function("1000x4KiB", |b| {
        b.iter(|| {
            let report = Verifier::new(small.path())
                .verify()
                .expect("verification runs");
            assert!(report.success());
            black_box(report)
        });
    });
    for jobs in [2, 4, 8] {
        group.bench_function(format!("1000x4KiB-jobs{jobs}"), |b| {
            b.iter(|| {
                let report = Verifier::new(small.path())
                    .jobs(NonZeroUsize::new(jobs).expect("the bench worker counts are positive"))
                    .verify()
                    .expect("verification runs");
                assert!(report.success());
                black_box(report)
            });
        });
    }

    let large = tempfile::tempdir().expect("create temp store");
    Generator::builder(large.path())
        .max_files(8)
        .file_sizes(SizeChooser::fixed(8 * 1024 * 1024))
        .build()
        .generate()
        .expect("generation succeeds");
    group.throughput(Throughput::Bytes(8 * 8 * 1024 * 1024));
    group.bench_function("8x8MiB", |b| {
        b.iter(|| {
            let report = Verifier::new(large.path())
                .verify()
                .expect("verification runs");
            assert!(report.success());
            black_box(report)
        });
    });
    for jobs in [2, 4] {
        group.bench_function(format!("8x8MiB-jobs{jobs}"), |b| {
            b.iter(|| {
                let report = Verifier::new(large.path())
                    .jobs(NonZeroUsize::new(jobs).expect("the bench worker counts are positive"))
                    .verify()
                    .expect("verification runs");
                assert!(report.success());
                black_box(report)
            });
        });
    }

    // One 8 MiB file with a corrupted byte in every megabyte: measures
    // the analysis path (full SHAKE regeneration plus chunked
    // comparison) at the default 4,096-byte analysis chunk size.
    let corrupt = tempfile::tempdir().expect("create temp store");
    Generator::builder(corrupt.path())
        .max_files(1)
        .file_sizes(SizeChooser::fixed(8 * 1024 * 1024))
        .build()
        .generate()
        .expect("generation succeeds");
    corrupt_every_mebibyte(corrupt.path());
    group.throughput(Throughput::Bytes(8 * 1024 * 1024));
    group.bench_function("corrupt-8MiB", |b| {
        b.iter(|| {
            let report = Verifier::new(corrupt.path())
                .verify()
                .expect("verification runs");
            assert!(!report.success());
            black_box(report)
        });
    });

    group.finish();
}

/// Flips one byte at every 1 MiB boundary (offset by half a block so
/// block 0's shortened length does not matter) of the store's only file.
fn corrupt_every_mebibyte(store: &std::path::Path) {
    fn find_file(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("store directories are readable") {
            let path = entry.expect("directory entries are readable").path();
            if path.file_name().is_some_and(|name| name == ".metadata") {
                continue;
            }
            if path.is_dir() {
                find_file(&path, out);
            } else {
                out.push(path);
            }
        }
    }
    let mut files = Vec::new();
    find_file(store, &mut files);
    let [path] = &*files else {
        panic!("expected exactly one data file");
    };
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .expect("data files are writable");
    for mib in 0..8_u64 {
        file.seek(SeekFrom::Start(mib * 1024 * 1024 + 512 * 1024))
            .expect("seek succeeds");
        file.write_all(&[0xFF]).expect("write succeeds");
    }
}

fn size_selection(c: &mut Criterion) {
    c.bench_function("size/parse-spec", |b| {
        b.iter(|| {
            black_box("Type=lognormal,Mean=16,StdDev=1")
                .parse::<SizeSpec>()
                .expect("the spec parses")
        });
    });

    c.bench_function("size/sample-lognormal", |b| {
        let mut sizes = SizeSpec::lognormal(16.0, 1.0)
            .expect("parameters are valid")
            .chooser()
            .expect("the random source works");
        b.iter(|| sizes.next_size().expect("samples are finite"));
    });

    c.bench_function("size/sample-range", |b| {
        let mut sizes = SizeSpec::range(1024..=2048)
            .expect("the range is not empty")
            .chooser()
            .expect("the random source works");
        b.iter(|| sizes.next_size().expect("range sampling cannot fail"));
    });
}

criterion_group!(benches, generation, verification, size_selection);
criterion_main!(benches);
