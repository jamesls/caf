//! Store-level integration tests for verification.
//!
//! The tests assert on structured results rather than terminal output.
//! Cases cover short reads, permission failures, truncation, extra bytes,
//! bad paths, missing parents, missing roots, orphaned files, serial and
//! parallel equivalence, and the iterative-walk nesting bound.

use std::fs::{self, OpenOptions};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use caf_format::{ContentReader, ContentSeed, Digest, HEADER_SIZE, Hasher, Header, hash_to_path};
use caf_store::{
    CorruptionClass, CorruptionPattern, Diagnostic, GenerationReport, Generator, Severity,
    SizeChooser, VerificationReport, Verifier,
};

fn generate(root: &Path, files: u64, size: u64) -> GenerationReport {
    Generator::builder(root)
        .max_files(files)
        .file_sizes(SizeChooser::fixed(size))
        .build()
        .generate()
        .expect("generation succeeds")
}

fn verify(root: &Path) -> VerificationReport {
    Verifier::new(root).verify().expect("verification runs")
}

fn verify_chunked(root: &Path, chunk_size: usize) -> VerificationReport {
    Verifier::new(root)
        .analysis_chunk_size(positive(chunk_size))
        .verify()
        .expect("verification runs")
}

/// The tests only use positive worker and chunk counts.
fn positive(value: usize) -> NonZeroUsize {
    NonZeroUsize::new(value).expect("the tests use positive settings")
}

/// What one level of the walk leaves out.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Skip<'a> {
    /// Skip this directory: the store root's own `.metadata`.
    Path(&'a Path),
    /// Skip nothing, which is every level below the root.
    Nothing,
}

/// Data files in the store, sorted byte-wise like the verifier's walk.
fn data_files(root: &Path) -> Vec<PathBuf> {
    fn walk(dir: &Path, skip: Skip, out: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(dir).expect("store directories are readable") {
            let path = entry.expect("directory entries are readable").path();
            if skip == Skip::Path(path.as_path()) {
                continue;
            }
            if path.is_dir() {
                walk(&path, Skip::Nothing, out);
            } else {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(root, Skip::Path(root.join(".metadata").as_path()), &mut out);
    out.sort_unstable_by(|a, b| {
        a.as_os_str()
            .as_encoded_bytes()
            .cmp(b.as_os_str().as_encoded_bytes())
    });
    out
}

fn overwrite(path: &Path, offset: u64, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .open(path)
        .expect("data files are writable");
    file.seek(SeekFrom::Start(offset)).expect("seek succeeds");
    file.write_all(bytes).expect("write succeeds");
}

fn truncate(path: &Path, new_len: u64) {
    OpenOptions::new()
        .write(true)
        .open(path)
        .expect("data files are writable")
        .set_len(new_len)
        .expect("truncate succeeds");
}

/// Reads the parent digest from a data file's header.
fn parent_of(root: &Path, digest: Digest) -> Digest {
    let bytes = fs::read(hash_to_path(root, digest)).expect("chain files exist");
    Header::parse(&bytes)
        .expect("chain headers are valid")
        .parent()
}

/// Writes `.metadata/roots` markers and a matching `.metadata/all`.
fn write_roots_metadata(root: &Path, markers: &[&str]) {
    let roots_dir = root.join(".metadata").join("roots");
    fs::create_dir_all(&roots_dir).expect("create the roots directory");
    let mut names: Vec<&str> = markers.to_vec();
    names.sort_unstable();
    let mut hasher = Hasher::new();
    for name in &names {
        fs::File::create(roots_dir.join(name)).expect("create a marker");
        hasher.update(name.as_bytes());
    }
    fs::write(
        root.join(".metadata").join("all"),
        hasher.finalize().to_hex(),
    )
    .expect("write the aggregate");
}

/// Builds the bytes of a self-consistent chain file (valid header
/// naming `parent` and deterministic content) of `file_length` bytes.
fn chain_file_bytes(parent: Digest, seed: ContentSeed, file_length: u64) -> Vec<u8> {
    let header = Header::new(parent, seed, file_length).expect("length is legal");
    let mut bytes = header.encode().to_vec();
    let content_length = usize::try_from(file_length).expect("test sizes are small") - HEADER_SIZE;
    let mut content = vec![0_u8; content_length];
    ContentReader::new(seed)
        .read_exact(&mut content)
        .expect("the content stream is infinite");
    bytes.extend_from_slice(&content);
    bytes
}

/// Builds the bytes of a self-consistent root file (zero parent).
fn clean_file_bytes(seed: ContentSeed, file_length: u64) -> Vec<u8> {
    chain_file_bytes(Digest::ZERO, seed, file_length)
}

/// Writes `bytes` at their whole-file digest's path and returns the
/// digest.
fn place_file(root: &Path, bytes: &[u8]) -> Digest {
    let digest = Digest::compute(bytes);
    let path = hash_to_path(root, digest);
    fs::create_dir_all(path.parent().expect("hash paths have parents"))
        .expect("create shard directories");
    fs::write(&path, bytes).expect("write the file");
    digest
}

// --- Python test equivalents (tests/test_verifier.py) ---

#[test]
fn clean_store_verifies() {
    // test_verify_files_succeeds_for_clean_files
    let store = tempfile::tempdir().expect("create temp store");
    generate(store.path(), 3, 1024);
    let report = verify(store.path());
    assert!(report.success());
    assert_eq!(report.files_checked(), 3);
    assert!(report.diagnostics().is_empty());
}

#[test]
fn detects_invalid_checksum() {
    // test_verify_files_detects_invalid_checksum
    let store = tempfile::tempdir().expect("create temp store");
    generate(store.path(), 1, 1024);
    let [file] = &*data_files(store.path()) else {
        panic!("exactly one data file is generated");
    };
    overwrite(file, 100, &b"corrupt_data".repeat(20));

    let report = verify(store.path());
    assert!(!report.success());
    let [corruption] = &*report.corruption_reports().collect::<Vec<_>>() else {
        panic!("exactly one corruption report: {:?}", report.diagnostics());
    };
    assert_eq!(corruption.path(), file);
    assert_eq!(corruption.class(), CorruptionClass::Content);
}

#[test]
fn detects_corrupted_root_metadata() {
    // test_verify_files_detects_corrupted_root_metadata ("Root hash is
    // not valid")
    let store = tempfile::tempdir().expect("create temp store");
    generate(store.path(), 1, 100);
    fs::write(store.path().join(".metadata").join("all"), b"bad").expect("overwrite the aggregate");

    let report = verify(store.path());
    assert!(!report.success());
    let [diagnostic] = report.diagnostics() else {
        panic!("exactly one diagnostic: {:?}", report.diagnostics());
    };
    assert!(
        matches!(
            diagnostic,
            Diagnostic::RootsMismatch { stored, .. } if stored == b"bad"
        ),
        "{diagnostic:?}"
    );
    assert_eq!(diagnostic.severity(), Severity::Corruption);
}

#[test]
fn detects_invalid_file_content() {
    // test_verify_files_detects_invalid_file_content: a zeroed header
    // fails its checksum ("Header corrupted" in Python).
    let store = tempfile::tempdir().expect("create temp store");
    let dir = store.path().join("aa").join("bb").join("cc");
    fs::create_dir_all(&dir).expect("create shard directories");
    let file = dir.join("0".repeat(34));
    fs::write(&file, [&[0_u8; 60][..], b"invalid data"].concat()).expect("write the file");
    write_roots_metadata(store.path(), &["dummy"]);

    let report = verify(store.path());
    assert!(!report.success());
    assert!(
        report.diagnostics().iter().any(|diagnostic| matches!(
            diagnostic,
            Diagnostic::InvalidHeader { path, source }
                if path == &file && source.is_checksum_mismatch()
        )),
        "{:?}",
        report.diagnostics()
    );
}

#[test]
fn four_level_layout_is_reported_and_orphaned() {
    // A file in a four-level layout is invalid and is also reported as
    // an orphan.
    let store = tempfile::tempdir().expect("create temp store");
    let seed = ContentSeed::from_bytes(*b"four-level-seed!");
    let bytes = clean_file_bytes(seed, 1024);
    let hex = Digest::compute(&bytes).to_hex();
    let dir = store
        .path()
        .join(&hex[0..2])
        .join(&hex[2..4])
        .join(&hex[4..6])
        .join(&hex[6..8]);
    fs::create_dir_all(&dir).expect("create shard directories");
    let file = dir.join(&hex[8..]);
    fs::write(&file, &bytes).expect("write the file");
    write_roots_metadata(store.path(), &[&hex]);

    let report = verify(store.path());
    assert!(!report.success());
    assert_eq!(report.files_checked(), 1);
    let [layout, orphan] = report.diagnostics() else {
        panic!("exactly two diagnostics: {:?}", report.diagnostics());
    };
    assert!(matches!(layout, Diagnostic::InvalidPathLayout { path } if path == &file));
    assert_eq!(layout.severity(), Severity::Error);
    assert!(matches!(orphan, Diagnostic::OrphanedFile { path } if path == &file));
    assert_eq!(orphan.severity(), Severity::Orphan);
}

#[test]
fn detects_zeroed_content() {
    // test_verify_files_detects_zeroed_content ("CONTENT CORRUPTED")
    let store = tempfile::tempdir().expect("create temp store");
    generate(store.path(), 2, 2048);
    let files = data_files(store.path());
    overwrite(&files[0], 100, &[0_u8; 500]);

    let report = verify(store.path());
    assert!(!report.success());
    let [corruption] = &*report.corruption_reports().collect::<Vec<_>>() else {
        panic!("exactly one corruption report: {:?}", report.diagnostics());
    };
    assert_eq!(corruption.class(), CorruptionClass::Content);
    assert!(corruption.total_corrupted_bytes() > 0);
}

#[test]
fn truncated_file_reports_a_truncated_region() {
    // test_verify_files_reports_truncated_file_as_corruption
    let store = tempfile::tempdir().expect("create temp store");
    generate(store.path(), 1, 4096);
    let [file] = &*data_files(store.path()) else {
        panic!("exactly one data file is generated");
    };
    truncate(file, 4096 - 512);

    let report = verify_chunked(store.path(), 256);
    assert!(!report.success());
    let [size_mismatch, digest_mismatch] = report.diagnostics() else {
        panic!("exactly two diagnostics: {:?}", report.diagnostics());
    };
    assert!(matches!(
        size_mismatch,
        Diagnostic::SizeMismatch {
            expected: 4096,
            actual: 3584,
            ..
        }
    ));
    let Diagnostic::DigestMismatch { report: corruption } = digest_mismatch else {
        panic!("expected a digest mismatch: {digest_mismatch:?}");
    };
    // Content before the truncation point is intact, so the only region
    // is the truncated tail; the class is content, not path mismatch.
    assert_eq!(corruption.class(), CorruptionClass::Content);
    let [region] = corruption.regions() else {
        panic!("exactly one region: {:?}", corruption.regions());
    };
    assert_eq!(region.offset(), 3584);
    assert_eq!(region.size(), 512);
    assert!(
        matches!(
            region.pattern(),
            CorruptionPattern::Truncated {
                missing_bytes: 512,
                ..
            }
        ),
        "{:?}",
        region.pattern()
    );
}

#[test]
fn chunk_size_never_affects_success() {
    // test_verify_files_with_different_chunk_sizes, extended to a
    // corrupted store: the chunk size changes region granularity only.
    let store = tempfile::tempdir().expect("create temp store");
    generate(store.path(), 1, 4096);
    for chunk_size in [256, 1024, 2048] {
        assert!(verify_chunked(store.path(), chunk_size).success());
    }

    let [file] = &*data_files(store.path()) else {
        panic!("exactly one data file is generated");
    };
    overwrite(file, 700, &[0xEE; 64]);
    for chunk_size in [1, 256, 4096, 65536] {
        let report = verify_chunked(store.path(), chunk_size);
        assert!(!report.success(), "chunk size {chunk_size}");
        let [corruption] = &*report.corruption_reports().collect::<Vec<_>>() else {
            panic!("exactly one corruption report at chunk size {chunk_size}");
        };
        assert!(
            corruption
                .regions()
                .iter()
                .any(|region| region.offset() <= 700 && 700 < region.end()),
            "chunk size {chunk_size}: {:?}",
            corruption.regions()
        );
    }
}

#[test]
fn broken_chain_reports_missing_parent_and_orphan() {
    // test_verify_files_detects_broken_file_chain: deleting a mid-chain
    // file breaks its child's parent link and orphans its own parent.
    let store = tempfile::tempdir().expect("create temp store");
    let generation = generate(store.path(), 5, 1024);
    assert!(verify(store.path()).success());

    let tip = generation.chain_tip();
    let child = parent_of(store.path(), tip); // references the victim
    let victim = parent_of(store.path(), child);
    let orphaned = parent_of(store.path(), victim);
    fs::remove_file(hash_to_path(store.path(), victim)).expect("delete the mid-chain file");

    let report = verify(store.path());
    assert!(!report.success());
    assert_eq!(report.files_checked(), 4);
    let [missing_parent, orphan] = report.diagnostics() else {
        panic!("exactly two diagnostics: {:?}", report.diagnostics());
    };
    assert!(
        matches!(
            missing_parent,
            Diagnostic::MissingParent { path, parent, parent_path }
                if *parent == victim
                    && path == &hash_to_path(store.path(), child)
                    && parent_path == &hash_to_path(store.path(), victim)
        ),
        "{missing_parent:?}"
    );
    assert!(
        matches!(
            orphan,
            Diagnostic::OrphanedFile { path }
                if path == &hash_to_path(store.path(), orphaned)
        ),
        "{orphan:?}"
    );
}

#[test]
fn detects_corrupted_metadata_aggregate() {
    // test_verify_files_detects_corrupted_metadata
    let store = tempfile::tempdir().expect("create temp store");
    generate(store.path(), 2, 1024);
    fs::write(
        store.path().join(".metadata").join("all"),
        b"corrupted_metadata",
    )
    .expect("overwrite the aggregate");

    let report = verify(store.path());
    assert!(!report.success());
    assert!(
        report
            .diagnostics()
            .iter()
            .any(|diagnostic| matches!(diagnostic, Diagnostic::RootsMismatch { .. })),
        "{:?}",
        report.diagnostics()
    );
}

#[test]
fn zero_filled_corruption_merges_whole_chunks() {
    // test_verify_files_reports_zero_filled_corruption. With a 256-byte
    // chunk size, zeroing 1000..2024 fully covers the three chunks at
    // 1084..1852, which must merge into one zero-filled region.
    let store = tempfile::tempdir().expect("create temp store");
    generate(store.path(), 1, 4096);
    let [file] = &*data_files(store.path()) else {
        panic!("exactly one data file is generated");
    };
    overwrite(file, 1000, &[0_u8; 1024]);

    let report = verify_chunked(store.path(), 256);
    assert!(!report.success());
    let [corruption] = &*report.corruption_reports().collect::<Vec<_>>() else {
        panic!("exactly one corruption report");
    };
    let zero_filled: Vec<_> = corruption
        .regions()
        .iter()
        .filter(|region| region.pattern() == CorruptionPattern::ZeroFilled)
        .collect();
    let [merged] = &*zero_filled else {
        panic!("one merged zero-filled region: {:?}", corruption.regions());
    };
    assert_eq!(merged.offset(), 1084);
    assert_eq!(merged.size(), 768);
}

#[test]
fn repeated_byte_corruption_reports_the_value() {
    // test_verify_files_reports_repeated_byte_corruption
    let store = tempfile::tempdir().expect("create temp store");
    generate(store.path(), 1, 4096);
    let [file] = &*data_files(store.path()) else {
        panic!("exactly one data file is generated");
    };
    overwrite(file, 1500, &[0xFF; 1024]);

    let report = verify_chunked(store.path(), 512);
    assert!(!report.success());
    let [corruption] = &*report.corruption_reports().collect::<Vec<_>>() else {
        panic!("exactly one corruption report");
    };
    assert!(
        corruption.regions().iter().any(|region| matches!(
            region.pattern(),
            CorruptionPattern::RepeatedByte { value: 0xFF, .. }
        )),
        "{:?}",
        corruption.regions()
    );
}

#[test]
fn distinct_corruption_areas_yield_multiple_regions() {
    // Structured equivalent of
    // test_verify_files_generates_corruption_visualization: two separate
    // corrupted areas produce distinct regions with their own patterns
    // (the CLI tests cover bar rendering).
    let store = tempfile::tempdir().expect("create temp store");
    generate(store.path(), 1, 8192);
    let [file] = &*data_files(store.path()) else {
        panic!("exactly one data file is generated");
    };
    overwrite(file, 500, &[0_u8; 500]);
    overwrite(file, 7000, &[0xFF; 500]);

    let report = verify_chunked(store.path(), 256);
    let [corruption] = &*report.corruption_reports().collect::<Vec<_>>() else {
        panic!("exactly one corruption report");
    };
    assert!(
        corruption.regions().len() >= 2,
        "{:?}",
        corruption.regions()
    );
    let patterns: Vec<&str> = corruption
        .regions()
        .iter()
        .map(|region| region.pattern().name())
        .collect();
    assert!(patterns.contains(&"zero-filled"), "{patterns:?}");
    assert!(patterns.contains(&"repeated-byte"), "{patterns:?}");
}

// --- Additional error coverage ---------------------------------------

#[test]
fn extra_bytes_report_size_mismatch_and_region() {
    let store = tempfile::tempdir().expect("create temp store");
    generate(store.path(), 1, 4096);
    let [file] = &*data_files(store.path()) else {
        panic!("exactly one data file is generated");
    };
    let mut existing = fs::read(file).expect("data files are readable");
    existing.extend_from_slice(&[0xAB; 100]);
    fs::write(file, existing).expect("append extra bytes");

    let report = verify(store.path());
    assert!(!report.success());
    let [size_mismatch, digest_mismatch] = report.diagnostics() else {
        panic!("exactly two diagnostics: {:?}", report.diagnostics());
    };
    assert!(matches!(
        size_mismatch,
        Diagnostic::SizeMismatch {
            expected: 4096,
            actual: 4196,
            ..
        }
    ));
    let Diagnostic::DigestMismatch { report: corruption } = digest_mismatch else {
        panic!("expected a digest mismatch: {digest_mismatch:?}");
    };
    assert_eq!(corruption.class(), CorruptionClass::Content);
    let [region] = corruption.regions() else {
        panic!("exactly one region: {:?}", corruption.regions());
    };
    assert_eq!(region.offset(), 4096);
    assert!(
        matches!(
            region.pattern(),
            CorruptionPattern::ExtraBytes {
                extra_count: 100,
                ..
            }
        ),
        "{:?}",
        region.pattern()
    );
}

#[test]
fn partial_header_is_an_invalid_header() {
    // A file shorter than 60 bytes cannot be validated further; the
    // short read surfaces as a truncated-header diagnostic, nothing
    // else (the size check runs only after the header parses).
    let store = tempfile::tempdir().expect("create temp store");
    generate(store.path(), 1, 4096);
    let [file] = &*data_files(store.path()) else {
        panic!("exactly one data file is generated");
    };
    truncate(file, 30);

    let report = verify(store.path());
    assert!(!report.success());
    let [diagnostic] = report.diagnostics() else {
        panic!("exactly one diagnostic: {:?}", report.diagnostics());
    };
    assert!(
        matches!(
            diagnostic,
            Diagnostic::InvalidHeader { source, .. } if source.is_truncated()
        ),
        "{diagnostic:?}"
    );
}

#[test]
fn nonzero_reserved_bytes_fail_verification() {
    // A self-consistent file (path matches the real
    // digest, valid checksum) with nonzero reserved bytes passes Python
    // `verify` but must fail the Rust verifier as an invalid header.
    let store = tempfile::tempdir().expect("create temp store");
    let seed = ContentSeed::from_bytes(*b"reserved-quirk!!");
    let mut bytes = clean_file_bytes(seed, 1024);
    bytes[55] = 0xFF; // Inside the reserved range; not checksummed.
    let digest = Digest::compute(&bytes);
    let path = hash_to_path(store.path(), digest);
    fs::create_dir_all(path.parent().expect("hash paths have parents"))
        .expect("create shard directories");
    fs::write(&path, &bytes).expect("write the file");
    write_roots_metadata(store.path(), &[&digest.to_hex()]);

    let report = verify(store.path());
    assert!(!report.success());
    let [diagnostic] = report.diagnostics() else {
        panic!("exactly one diagnostic: {:?}", report.diagnostics());
    };
    assert!(
        matches!(
            diagnostic,
            Diagnostic::InvalidHeader { source, .. } if source.is_reserved_not_zero()
        ),
        "{diagnostic:?}"
    );
}

#[test]
fn wrong_path_classifies_as_path_mismatch() {
    // Valid content stored under a different digest's path: zero
    // corrupted bytes, equal sizes, class path-mismatch; the copy is
    // also an orphan because nothing references its path digest.
    let store = tempfile::tempdir().expect("create temp store");
    generate(store.path(), 1, 512);
    let [file] = &*data_files(store.path()) else {
        panic!("exactly one data file is generated");
    };
    let bytes = fs::read(file).expect("data files are readable");
    let real_digest = Digest::compute(&bytes);
    let mut hex = real_digest.to_hex();
    let flipped = if hex.starts_with('0') { "f" } else { "0" };
    hex.replace_range(0..1, flipped);
    let wrong_digest = Digest::from_hex(&hex).expect("still valid hex");
    let wrong_path = hash_to_path(store.path(), wrong_digest);
    fs::create_dir_all(wrong_path.parent().expect("hash paths have parents"))
        .expect("create shard directories");
    fs::write(&wrong_path, &bytes).expect("write the copy");

    let report = verify(store.path());
    assert!(!report.success());
    assert_eq!(report.files_checked(), 2);
    let [digest_mismatch, orphan] = report.diagnostics() else {
        panic!("exactly two diagnostics: {:?}", report.diagnostics());
    };
    let Diagnostic::DigestMismatch { report: corruption } = digest_mismatch else {
        panic!("expected a digest mismatch: {digest_mismatch:?}");
    };
    assert_eq!(corruption.class(), CorruptionClass::PathMismatch);
    assert_eq!(corruption.total_corrupted_bytes(), 0);
    assert_eq!(corruption.expected_digest(), wrong_digest);
    assert_eq!(corruption.actual_digest(), real_digest);
    assert!(matches!(orphan, Diagnostic::OrphanedFile { path } if path == &wrong_path));
}

#[test]
fn stray_temp_file_is_loudly_reported() {
    // A leftover temporary in the store root never
    // matches the layout, so it is reported (and orphan-checked).
    let store = tempfile::tempdir().expect("create temp store");
    generate(store.path(), 1, 512);
    let stray = store.path().join("00000000000000001234abcd");
    fs::write(&stray, b"interrupted write").expect("write the stray file");

    let report = verify(store.path());
    assert!(!report.success());
    assert_eq!(report.files_checked(), 2);
    let [layout, orphan] = report.diagnostics() else {
        panic!("exactly two diagnostics: {:?}", report.diagnostics());
    };
    assert!(matches!(layout, Diagnostic::InvalidPathLayout { path } if path == &stray));
    assert!(matches!(orphan, Diagnostic::OrphanedFile { path } if path == &stray));
}

#[test]
fn missing_roots_directory_is_not_a_store() {
    // Python: "not a valid CAF store (missing .metadata/roots)".
    let store = tempfile::tempdir().expect("create temp store");
    fs::create_dir(store.path().join(".metadata")).expect("create .metadata only");
    let err = Verifier::new(store.path())
        .verify()
        .expect_err("a store without roots is invalid");
    assert!(err.is_not_a_store());
}

#[test]
fn missing_aggregate_is_an_io_error() {
    // Python crashed with a FileNotFoundError traceback; the Rust
    // verifier reports a structured error naming `.metadata/all`
    // (documented divergence, same failed outcome).
    let store = tempfile::tempdir().expect("create temp store");
    generate(store.path(), 1, 512);
    let all_path = store.path().join(".metadata").join("all");
    fs::remove_file(&all_path).expect("delete the aggregate");

    let err = Verifier::new(store.path())
        .verify()
        .expect_err("the aggregate is required");
    assert!(err.is_io());
    assert_eq!(err.path(), Some(all_path.as_path()));
}

#[test]
fn diagnostics_are_ordered_by_sorted_path() {
    // Report order is deterministic and byte-wise on the path.
    let store = tempfile::tempdir().expect("create temp store");
    generate(store.path(), 3, 2048);
    let files = data_files(store.path());
    overwrite(&files[0], 100, b"junk");
    overwrite(&files[2], 100, b"junk");

    let report = verify(store.path());
    let reported: Vec<&Path> = report
        .corruption_reports()
        .map(caf_store::CorruptionReport::path)
        .collect();
    assert_eq!(reported, vec![files[0].as_path(), files[2].as_path()]);
}

#[test]
fn metadata_substring_in_the_store_path_changes_nothing() {
    // The Python implementation skipped every directory whose full path
    // merely contained the substring ".metadata" and would verify this
    // store trivially; Rust must verify its files normally.
    let base = tempfile::tempdir().expect("create temp dir");
    let store = base.path().join("backup.metadata-store");
    generate(&store, 3, 512);
    let report = verify(&store);
    assert!(report.success());
    assert_eq!(report.files_checked(), 3);
}

#[test]
fn nested_metadata_directory_is_not_skipped() {
    // Only the `.metadata` child of the store root is
    // special. A nested `.metadata` directory is walked and its files
    // are outside the layout, so they are loudly reported (Python
    // silently skipped them).
    let store = tempfile::tempdir().expect("create temp store");
    generate(store.path(), 1, 512);
    let nested = store.path().join("aa").join(".metadata");
    fs::create_dir_all(&nested).expect("create the nested directory");
    fs::write(nested.join("stowaway"), b"data").expect("write the nested file");

    let report = verify(store.path());
    assert!(!report.success());
    assert!(
        report.diagnostics().iter().any(|diagnostic| matches!(
            diagnostic,
            Diagnostic::InvalidPathLayout { path } if path == &nested.join("stowaway")
        )),
        "{:?}",
        report.diagnostics()
    );
}

#[cfg(unix)]
#[test]
fn unreadable_data_file_is_an_io_error() {
    use std::os::unix::fs::PermissionsExt as _;

    let store = tempfile::tempdir().expect("create temp store");
    generate(store.path(), 1, 512);
    let [file] = &*data_files(store.path()) else {
        panic!("exactly one data file is generated");
    };
    fs::set_permissions(file, fs::Permissions::from_mode(0o000)).expect("drop permissions");
    if fs::read(file).is_ok() {
        eprintln!("skipping: running with CAP_DAC_OVERRIDE (root)");
        return;
    }

    let err = Verifier::new(store.path())
        .verify()
        .expect_err("the file is unreadable");
    assert!(err.is_io());
    assert_eq!(err.path(), Some(file.as_path()));
    fs::set_permissions(file, fs::Permissions::from_mode(0o644)).expect("restore permissions");
}

#[cfg(unix)]
#[test]
fn unreadable_directory_is_an_io_error() {
    use std::os::unix::fs::PermissionsExt as _;

    // Python's os.walk silently skipped unreadable directories, which
    // could verify nothing and still succeed; the Rust verifier reports
    // a structured error instead (documented divergence).
    let store = tempfile::tempdir().expect("create temp store");
    generate(store.path(), 1, 512);
    let [file] = &*data_files(store.path()) else {
        panic!("exactly one data file is generated");
    };
    let shard = file.parent().expect("data files live in shard directories");
    fs::set_permissions(shard, fs::Permissions::from_mode(0o000)).expect("drop permissions");
    if fs::read_dir(shard).is_ok() {
        fs::set_permissions(shard, fs::Permissions::from_mode(0o755)).expect("restore");
        eprintln!("skipping: running with CAP_DAC_OVERRIDE (root)");
        return;
    }

    let err = Verifier::new(store.path())
        .verify()
        .expect_err("the directory is unreadable");
    assert!(err.is_io());
    assert_eq!(err.path(), Some(shard));
    fs::set_permissions(shard, fs::Permissions::from_mode(0o755)).expect("restore permissions");
}

#[cfg(unix)]
#[test]
fn directory_symlink_contents_are_invisible() {
    // Directory symlinks are not followed; their contents
    // are neither verified nor orphan-checked.
    let base = tempfile::tempdir().expect("create temp dir");
    let store = base.path().join("store");
    generate(&store, 2, 512);
    let side = base.path().join("side");
    fs::create_dir(&side).expect("create the side directory");
    fs::write(side.join("junk"), b"not a caf file").expect("write junk");
    std::os::unix::fs::symlink(&side, store.join("linked")).expect("create the dir symlink");

    let report = verify(&store);
    assert!(report.success());
    assert_eq!(report.files_checked(), 2);
}

#[cfg(unix)]
#[test]
fn file_symlinks_are_followed() {
    // Symlinked files verify like regular files.
    let base = tempfile::tempdir().expect("create temp dir");
    let store = base.path().join("store");
    generate(&store, 1, 512);
    let [file] = &*data_files(&store) else {
        panic!("exactly one data file is generated");
    };
    let target = base.path().join("relocated");
    fs::rename(file, &target).expect("move the data file");
    std::os::unix::fs::symlink(&target, file).expect("create the file symlink");

    assert!(verify(&store).success());

    // Corruption behind the symlink is still detected.
    overwrite(&target, 100, b"junk");
    let report = verify(&store);
    assert!(!report.success());
    assert_eq!(report.corruption_reports().count(), 1);
}

#[cfg(target_os = "linux")]
#[test]
fn non_utf8_file_name_is_loudly_reported() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt as _;

    // A non-UTF-8 file name inside the store cannot be hex and surfaces
    // as a layout diagnostic carrying the exact original bytes, never a
    // crash or a lossy conversion. Linux-only: APFS on macOS rejects
    // non-UTF-8 names with EILSEQ, so the fixture cannot exist there.
    let store = tempfile::tempdir().expect("create temp store");
    generate(store.path(), 2, 512);
    assert!(verify(store.path()).success());

    let junk = store.path().join(OsStr::from_bytes(b"\xfe\xffjunk"));
    fs::write(&junk, b"data").expect("write the junk file");
    let report = verify(store.path());
    assert!(!report.success());
    let [layout, orphan] = report.diagnostics() else {
        panic!("exactly two diagnostics: {:?}", report.diagnostics());
    };
    assert!(matches!(layout, Diagnostic::InvalidPathLayout { path } if path == &junk));
    assert!(matches!(orphan, Diagnostic::OrphanedFile { path } if path == &junk));
}

#[test]
fn zero_file_store_verifies() {
    // The zero-file store (all-zero chain tip) is clean.
    let store = tempfile::tempdir().expect("create temp store");
    Generator::builder(store.path())
        .max_files(0)
        .build()
        .generate()
        .expect("generation succeeds");
    let report = verify(store.path());
    assert!(report.success());
    assert_eq!(report.files_checked(), 0);
}

#[test]
fn default_analysis_chunk_size_matches_python() {
    // The default for --chunk-size is 4096.
    assert_eq!(caf_store::DEFAULT_ANALYSIS_CHUNK_SIZE.get(), 4096);
}

// --- Bounded parallel verification and the walk bound ----------------

/// Deterministic, backtrace-free rendering of a diagnostic for
/// serial-vs-parallel equality checks (`HeaderError`'s `Debug` output
/// includes a captured backtrace, which differs between otherwise
/// identical diagnostics when backtraces are enabled).
fn diagnostic_key(diagnostic: &Diagnostic) -> String {
    match diagnostic {
        Diagnostic::InvalidPathLayout { path } => format!("layout {}", path.display()),
        Diagnostic::InvalidHeader { path, source } => {
            format!("header {} {source}", path.display())
        }
        Diagnostic::SizeMismatch {
            path,
            expected,
            actual,
        } => format!("size {} {expected} {actual}", path.display()),
        Diagnostic::DigestMismatch { report } => format!(
            "digest {} {} {} {} {:?}",
            report.path().display(),
            report.expected_digest(),
            report.actual_digest(),
            report.actual_size(),
            report.regions(),
        ),
        Diagnostic::MissingParent {
            path,
            parent,
            parent_path,
        } => format!(
            "parent {} {parent} {}",
            path.display(),
            parent_path.display()
        ),
        Diagnostic::OrphanedFile { path } => format!("orphan {}", path.display()),
        Diagnostic::RootsMismatch {
            path,
            stored,
            computed,
        } => format!("roots {} {stored:?} {computed}", path.display()),
        other => format!("{other:?}"),
    }
}

/// Verifies with `jobs` workers and requires a report identical to the
/// serial one: same counts, same success, same diagnostics in the same
/// order.
fn assert_matches_serial(store: &Path, serial: &VerificationReport, jobs: usize) {
    let parallel = Verifier::new(store)
        .jobs(positive(jobs))
        .verify()
        .expect("verification runs");
    assert_eq!(
        parallel.files_checked(),
        serial.files_checked(),
        "jobs {jobs}"
    );
    assert_eq!(parallel.success(), serial.success(), "jobs {jobs}");
    let serial_keys: Vec<String> = serial.diagnostics().iter().map(diagnostic_key).collect();
    let parallel_keys: Vec<String> = parallel.diagnostics().iter().map(diagnostic_key).collect();
    assert_eq!(parallel_keys, serial_keys, "jobs {jobs}");
}

#[test]
fn excessively_nested_directories_are_a_structured_error() {
    // The walk is iterative, and a pathologically nested tree yields a
    // structured error instead of a stack overflow.
    let store = tempfile::tempdir().expect("create temp store");
    generate(store.path(), 1, 512);
    let mut deep = store.path().join("zz");
    for _ in 0..70 {
        deep.push("d");
    }
    fs::create_dir_all(&deep).expect("create the nested directories");

    let err = Verifier::new(store.path())
        .verify()
        .expect_err("nesting beyond the walk bound is an error");
    assert!(err.is_excessive_nesting());
    assert!(!err.is_io());
    assert!(err.path().is_some());
    assert!(err.to_string().contains("nest more than"), "{err}");
}

#[test]
fn parallel_verification_matches_serial_on_a_clean_store() {
    let store = tempfile::tempdir().expect("create temp store");
    generate(store.path(), 30, 2048);
    let serial = verify(store.path());
    assert!(serial.success());
    for jobs in [1, 2, 4, 8] {
        assert_matches_serial(store.path(), &serial, jobs);
    }
}

#[test]
fn parallel_verification_matches_serial_on_a_corrupted_store() {
    // One store with every diagnostic family at once: content
    // corruption, truncation, a stray temp file, a wrong-path copy,
    // and a broken chain (missing parent plus orphan).
    let store = tempfile::tempdir().expect("create temp store");
    let generation = generate(store.path(), 12, 2048);
    let files = data_files(store.path());
    overwrite(&files[1], 100, b"corrupt_data");
    truncate(&files[3], 1024);
    fs::write(store.path().join("00000000000000005678cdef"), b"stray").expect("write the stray");
    let copy_bytes = fs::read(&files[5]).expect("data files are readable");
    let real_digest = Digest::compute(&copy_bytes);
    let mut hex = real_digest.to_hex();
    let flipped = if hex.starts_with('0') { "f" } else { "0" };
    hex.replace_range(0..1, flipped);
    let wrong_digest = Digest::from_hex(&hex).expect("still valid hex");
    let wrong_path = hash_to_path(store.path(), wrong_digest);
    fs::create_dir_all(wrong_path.parent().expect("hash paths have parents"))
        .expect("create shard directories");
    fs::write(&wrong_path, &copy_bytes).expect("write the copy");
    let victim = parent_of(store.path(), generation.chain_tip());
    fs::remove_file(hash_to_path(store.path(), victim)).expect("delete the mid-chain file");

    let serial = verify(store.path());
    assert!(!serial.success());
    assert!(
        serial.diagnostics().len() >= 6,
        "{:?}",
        serial.diagnostics()
    );
    for jobs in [2, 4, 8] {
        assert_matches_serial(store.path(), &serial, jobs);
    }
}

#[test]
fn parallel_verification_is_deterministic_under_uneven_load() {
    // Per-file cost varies widely (multi-megabyte files among tiny ones),
    // so workers finish out of order. Repeated parallel runs must still
    // reproduce the serial report exactly.
    let store = tempfile::tempdir().expect("create temp store");
    generate(store.path(), 3, 4 * 1024 * 1024);
    generate(store.path(), 30, 4096);
    let files = data_files(store.path());
    let large: Vec<&PathBuf> = files
        .iter()
        .filter(|file| fs::metadata(file).expect("data files are readable").len() > 1024 * 1024)
        .collect();
    let small: Vec<&PathBuf> = files
        .iter()
        .filter(|file| fs::metadata(file).expect("data files are readable").len() <= 4096)
        .collect();
    overwrite(large[0], 2000, &[0xAA; 100]);
    overwrite(small[0], 100, b"junk");
    overwrite(small[10], 100, b"junk");

    let serial = verify(store.path());
    assert!(!serial.success());
    for _ in 0..5 {
        assert_matches_serial(store.path(), &serial, 8);
    }
}

#[cfg(unix)]
#[test]
fn parallel_worker_errors_are_structured() {
    use std::os::unix::fs::PermissionsExt as _;

    // An unreadable file stops a parallel run with the same structured
    // error the serial run reports: the first error in sorted file
    // order, regardless of worker completion order.
    let store = tempfile::tempdir().expect("create temp store");
    generate(store.path(), 8, 512);
    let files = data_files(store.path());
    fs::set_permissions(&files[4], fs::Permissions::from_mode(0o000)).expect("drop permissions");
    if fs::read(&files[4]).is_ok() {
        eprintln!("skipping: running with CAP_DAC_OVERRIDE (root)");
        return;
    }

    for jobs in [1, 4] {
        let err = Verifier::new(store.path())
            .jobs(positive(jobs))
            .verify()
            .expect_err("the file is unreadable");
        assert!(err.is_io(), "jobs {jobs}");
        assert_eq!(err.path(), Some(files[4].as_path()), "jobs {jobs}");
    }
    fs::set_permissions(&files[4], fs::Permissions::from_mode(0o644)).expect("restore permissions");
}

#[test]
fn reserved_byte_flip_in_a_genuine_file_is_an_invalid_header() {
    // Flipping a reserved byte of a genuine generated file fails the
    // legacy Python implementation as PATH MISMATCH (content valid).
    // Rust rejects the invalid version 2 header before hashing.
    let store = tempfile::tempdir().expect("create temp store");
    generate(store.path(), 1, 1024);
    let [file] = &*data_files(store.path()) else {
        panic!("exactly one data file is generated");
    };
    overwrite(file, 55, &[0x01]); // The reserved range is bytes 52..60.

    let report = verify(store.path());
    assert!(!report.success());
    let [diagnostic] = report.diagnostics() else {
        panic!("exactly one diagnostic: {:?}", report.diagnostics());
    };
    assert!(
        matches!(
            diagnostic,
            Diagnostic::InvalidHeader { path, source }
                if path == file && source.is_reserved_not_zero()
        ),
        "{diagnostic:?}"
    );
}

#[test]
fn reserved_byte_mid_chain_file_cascades_to_a_false_orphan() {
    // A hand-crafted mid-chain file with
    // nonzero reserved bytes fails as an invalid header, so its parent
    // link is never read and the parent is additionally reported as a
    // false orphan. The legacy Python implementation accepted this
    // malformed store because it did not validate reserved bytes.
    let store = tempfile::tempdir().expect("create temp store");
    let parent_digest = place_file(
        store.path(),
        &clean_file_bytes(ContentSeed::from_bytes(*b"cascade-parent!!"), 512),
    );
    let mut tip_bytes = chain_file_bytes(
        parent_digest,
        ContentSeed::from_bytes(*b"cascade-tip-file"),
        512,
    );
    tip_bytes[55] = 0xFF; // Reserved range; not covered by the checksum.
    let tip_digest = place_file(store.path(), &tip_bytes);
    write_roots_metadata(store.path(), &[&tip_digest.to_hex()]);

    let report = verify(store.path());
    assert!(!report.success());
    assert_eq!(report.files_checked(), 2);
    let [header, orphan] = report.diagnostics() else {
        panic!("exactly two diagnostics: {:?}", report.diagnostics());
    };
    assert!(
        matches!(
            header,
            Diagnostic::InvalidHeader { path, source }
                if path == &hash_to_path(store.path(), tip_digest)
                    && source.is_reserved_not_zero()
        ),
        "{header:?}"
    );
    assert!(
        matches!(
            orphan,
            Diagnostic::OrphanedFile { path }
                if path == &hash_to_path(store.path(), parent_digest)
        ),
        "{orphan:?}"
    );
}

mod properties {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        /// Any in-place content corruption is detected with a region
        /// covering the corrupted offset, at any analysis chunk size.
        #[test]
        fn content_corruption_is_always_detected(
            file_size in 100_u64..4096,
            offset_fraction in 0.0_f64..1.0,
            corrupt_len in 1_usize..32,
            chunk_size in prop_oneof![Just(64_usize), Just(512), Just(4096)],
        ) {
            let store = tempfile::tempdir().expect("create temp store");
            generate(store.path(), 1, file_size);
            let [file] = &*data_files(store.path()) else {
                panic!("exactly one data file is generated");
            };

            let content_len = file_size - HEADER_SIZE as u64;
            #[expect(
                clippy::cast_precision_loss,
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "test sizes are tiny"
            )]
            let offset = HEADER_SIZE as u64 + (offset_fraction * (content_len - 1) as f64) as u64;
            let take = corrupt_len.min(usize::try_from(file_size - offset).expect("fits"));

            // XOR the range so every corrupted byte is guaranteed to
            // differ from the deterministic stream.
            let mut bytes = fs::read(file).expect("data files are readable");
            let end = usize::try_from(offset).expect("fits") + take;
            for byte in &mut bytes[usize::try_from(offset).expect("fits")..end] {
                *byte ^= 0xFF;
            }
            fs::write(file, &bytes).expect("write the corruption");

            let report = verify_chunked(store.path(), chunk_size);
            prop_assert!(!report.success());
            let reports: Vec<_> = report.corruption_reports().collect();
            prop_assert_eq!(reports.len(), 1);
            let corruption = reports[0];
            prop_assert_eq!(corruption.class(), CorruptionClass::Content);
            prop_assert!(
                corruption
                    .regions()
                    .iter()
                    .any(|region| region.offset() <= offset && offset < region.end()),
                "regions {:?} must cover offset {}",
                corruption.regions(),
                offset,
            );
        }
    }
}
