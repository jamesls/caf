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
//! - `verify/1x64MiB-jobsN`: one clean large file, exercising positional
//!   readers feeding one ordered digest.
//! - `verify/5x32MiB-jobsN`: spare-lane allocation across a small set of
//!   equal large files.
//! - `verify/corrupt-{start,middle,end}-32MiB-jobsN` — the
//!   corruption-analysis path (SHAKE regeneration plus chunk comparison
//!   at the default 4,096-byte analysis chunk size).
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
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
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
    let worker_counts = verification_worker_counts();

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

    let one_large = tempfile::tempdir().expect("create temp store");
    Generator::builder(one_large.path())
        .max_files(1)
        .file_sizes(SizeChooser::fixed(64 * 1024 * 1024))
        .build()
        .generate()
        .expect("generation succeeds");
    group.throughput(Throughput::Bytes(64 * 1024 * 1024));
    for &jobs in &worker_counts {
        group.bench_function(format!("1x64MiB-jobs{jobs}"), |b| {
            b.iter(|| {
                let report = Verifier::new(one_large.path())
                    .jobs(NonZeroUsize::new(jobs).expect("the bench worker counts are positive"))
                    .verify()
                    .expect("verification runs");
                assert!(report.success());
                black_box(report)
            });
        });
    }

    let five_large = tempfile::tempdir().expect("create temp store");
    Generator::builder(five_large.path())
        .max_files(5)
        .file_sizes(SizeChooser::fixed(32 * 1024 * 1024))
        .build()
        .generate()
        .expect("generation succeeds");
    group.throughput(Throughput::Bytes(5 * 32 * 1024 * 1024));
    for &jobs in &worker_counts {
        group.bench_function(format!("5x32MiB-jobs{jobs}"), |b| {
            b.iter(|| {
                let report = Verifier::new(five_large.path())
                    .jobs(NonZeroUsize::new(jobs).expect("the bench worker counts are positive"))
                    .verify()
                    .expect("verification runs");
                assert!(report.success());
                black_box(report)
            });
        });
    }

    // Damage near the start, middle, and end all trigger a full digest
    // followed by expected-content regeneration. Keeping them separate
    // catches any accidental dependence on the mismatch's position.
    group.throughput(Throughput::Bytes(32 * 1024 * 1024));
    for (position, offset) in [
        ("start", 512 * 1024_u64),
        ("middle", 16 * 1024 * 1024_u64),
        ("end", 32 * 1024 * 1024_u64 - 512 * 1024),
    ] {
        let corrupt = corrupted_store(offset);
        for &jobs in &worker_counts {
            group.bench_function(format!("corrupt-{position}-32MiB-jobs{jobs}"), |b| {
                b.iter(|| {
                    let report = Verifier::new(corrupt.path())
                        .jobs(
                            NonZeroUsize::new(jobs).expect("the bench worker counts are positive"),
                        )
                        .verify()
                        .expect("verification runs");
                    assert!(!report.success());
                    black_box(report)
                });
            });
        }
    }

    group.finish();
}

fn verification_worker_counts() -> Vec<usize> {
    let mut counts = vec![1, 2, 4, 8, 16];
    if let Ok(logical) = std::thread::available_parallelism() {
        counts.push(logical.get().min(caf_store::MAX_JOBS.get()));
    }
    counts.sort_unstable();
    counts.dedup();
    counts
}

/// Builds a 32 MiB one-file store and flips one byte at `offset`.
fn corrupted_store(offset: u64) -> tempfile::TempDir {
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

    let store = tempfile::tempdir().expect("create temp store");
    Generator::builder(store.path())
        .max_files(1)
        .file_sizes(SizeChooser::fixed(32 * 1024 * 1024))
        .build()
        .generate()
        .expect("generation succeeds");
    let mut files = Vec::new();
    find_file(store.path(), &mut files);
    let [path] = &*files else {
        panic!("expected exactly one data file");
    };
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .expect("data files are writable");
    file.seek(SeekFrom::Start(offset)).expect("seek succeeds");
    let mut byte = [0_u8];
    file.read_exact(&mut byte).expect("the byte is readable");
    byte[0] ^= 0xFF;
    file.seek(SeekFrom::Start(offset)).expect("seek succeeds");
    file.write_all(&byte).expect("write succeeds");
    store
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
