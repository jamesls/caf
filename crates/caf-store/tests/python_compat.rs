//! Two-way Python compatibility for generation and verification.
//!
//! Each producer-consumer direction is tested. The Rust producer cases
//! generate a store with the Rust library and run the Python
//! implementation's `caf verify` against it through `uv run`. The Python
//! producer cases generate stores that the Rust verifier reads. Corrupted
//! stores are also compared: both
//! implementations must agree on success, failure, and the semantic
//! diagnosis, except for the documented reserved-byte asymmetry.
//! When `uv` is not available (for example in the Rust-only CI jobs),
//! the tests skip with a note instead of failing.

use std::fs::{self, OpenOptions};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::process::Command;

use caf_format::{ContentReader, ContentSeed, Digest, HEADER_SIZE, Hasher, Header, hash_to_path};
use caf_store::{CorruptionClass, Diagnostic, Generator, SizeChooser, SizeSpec, Verifier};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the workspace lives inside the repository")
}

/// Returns `false` (and prints a skip note) when the Python oracle
/// cannot run here.
fn python_oracle_available() -> bool {
    let available = Command::new("uv")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success());
    if !available {
        eprintln!("skipping: `uv` is unavailable, cannot run the Python oracle");
    }
    available
}

fn python_verify(store: &Path) -> std::process::Output {
    Command::new("uv")
        .args(["run", "--project"])
        .arg(repo_root())
        .args(["caf", "verify", "--directory"])
        .arg(store)
        .current_dir(repo_root())
        .output()
        .expect("uv invocations run")
}

fn assert_python_verifies(store: &Path, label: &str) {
    let output = python_verify(store);
    assert!(
        output.status.success(),
        "{label}: Python rejected the Rust-generated store\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn python_verifies_rust_stores_for_every_size_mode() {
    if !python_oracle_available() {
        return;
    }
    // Every size-selection mode, including both endpoints of the
    // grammar (fixed, suffixed, range, and all three distributions) and
    // the 60-byte minimum.
    let modes = [
        "4096",
        "60",
        "2kb",
        "1kb-2kb",
        "60-60",
        "Type=normal,Mean=2kb,StdDev=1kb",
        "Type=gamma,Alpha=2,Beta=1kb",
        "Type=lognormal,Mean=8,StdDev=1",
    ];
    for mode in modes {
        let store = tempfile::tempdir().expect("create temp store");
        let spec: SizeSpec = mode.parse().unwrap_or_else(|err| panic!("{mode}: {err}"));
        Generator::builder(store.path())
            .max_files(5)
            .file_sizes(spec.chooser().unwrap_or_else(|err| panic!("{mode}: {err}")))
            .build()
            .generate()
            .unwrap_or_else(|err| panic!("{mode}: {err}"));
        assert_python_verifies(store.path(), mode);
    }
}

#[test]
fn python_verifies_a_rust_zero_file_store() {
    if !python_oracle_available() {
        return;
    }
    // The zero-file store (all-zero chain tip) must verify.
    let store = tempfile::tempdir().expect("create temp store");
    Generator::builder(store.path())
        .max_files(0)
        .build()
        .generate()
        .expect("generation succeeds");
    assert_python_verifies(store.path(), "zero-file store");
}

#[test]
fn python_verifies_multiple_rust_chains() {
    if !python_oracle_available() {
        return;
    }
    let store = tempfile::tempdir().expect("create temp store");
    for _ in 0..3 {
        Generator::builder(store.path())
            .max_files(2)
            .file_sizes(SizeChooser::fixed(512))
            .build()
            .generate()
            .expect("generation succeeds");
    }
    assert_python_verifies(store.path(), "three chains");
}

#[test]
fn python_verifies_a_rust_multi_block_file() {
    if !python_oracle_available() {
        return;
    }
    // Straddles the shortened block 0 / block 1 boundary.
    let store = tempfile::tempdir().expect("create temp store");
    Generator::builder(store.path())
        .max_files(1)
        .file_sizes(SizeChooser::fixed(1024 * 1024 + 4096))
        .build()
        .generate()
        .expect("generation succeeds");
    assert_python_verifies(store.path(), "multi-block file");
}

// --- Python producer, Rust consumer, and corrupted stores -------------

/// Generates a store with the Python implementation.
fn python_generate(store: &Path, max_files: u32, file_size: &str) {
    let output = Command::new("uv")
        .args(["run", "--project"])
        .arg(repo_root())
        .args(["caf", "gen", "--directory"])
        .arg(store)
        .args(["--max-files", &max_files.to_string()])
        .args(["--file-size", file_size])
        .current_dir(repo_root())
        .output()
        .expect("uv invocations run");
    assert!(
        output.status.success(),
        "Python generation failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

/// The single data file of a one-file store.
fn only_data_file(store: &Path) -> PathBuf {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(dir).expect("store directories are readable") {
            let path = entry.expect("directory entries are readable").path();
            if path.file_name().is_some_and(|name| name == ".metadata") {
                continue;
            }
            if path.is_dir() {
                walk(&path, out);
            } else {
                out.push(path);
            }
        }
    }
    let mut files = Vec::new();
    walk(store, &mut files);
    let [file] = &*files else {
        panic!("expected exactly one data file, found {files:?}");
    };
    file.clone()
}

#[test]
fn rust_verifies_clean_python_stores() {
    if !python_oracle_available() {
        return;
    }
    // Fixed sizes, a range, the 60-byte minimum, and a file straddling
    // the block 0 / block 1 boundary.
    for (max_files, file_size) in [(5, "4096"), (5, "1kb-2kb"), (3, "60"), (1, "1052736")] {
        let store = tempfile::tempdir().expect("create temp store");
        python_generate(store.path(), max_files, file_size);
        let report = Verifier::new(store.path())
            .verify()
            .expect("verification runs");
        assert!(
            report.success(),
            "{file_size}: Rust rejected the Python store: {:?}",
            report.diagnostics()
        );
        assert_eq!(report.files_checked(), u64::from(max_files), "{file_size}");
    }
}

#[test]
fn rust_verifies_appended_python_and_rust_chains() {
    if !python_oracle_available() {
        return;
    }
    // A store both implementations wrote into must verify under both.
    let store = tempfile::tempdir().expect("create temp store");
    python_generate(store.path(), 2, "512");
    Generator::builder(store.path())
        .max_files(2)
        .file_sizes(SizeChooser::fixed(512))
        .build()
        .generate()
        .expect("generation succeeds");

    let report = Verifier::new(store.path())
        .verify()
        .expect("verification runs");
    assert!(report.success(), "{:?}", report.diagnostics());
    assert_eq!(report.files_checked(), 4);
    assert_python_verifies(store.path(), "mixed-writer store");
}

#[test]
fn content_corruption_fails_both_implementations() {
    if !python_oracle_available() {
        return;
    }
    // Both implementations report the same semantic failure for an
    // invalid whole-file digest with corrupted content: exit 1 from
    // Python and a digest-mismatch diagnostic from Rust.
    let store = tempfile::tempdir().expect("create temp store");
    python_generate(store.path(), 1, "2048");
    let file = only_data_file(store.path());
    let mut handle = OpenOptions::new()
        .write(true)
        .open(&file)
        .expect("data files are writable");
    handle.seek(SeekFrom::Start(100)).expect("seek succeeds");
    handle.write_all(b"corrupt_data").expect("write succeeds");
    drop(handle);

    let python = python_verify(store.path());
    assert_eq!(python.status.code(), Some(1), "Python must fail");

    let report = Verifier::new(store.path())
        .verify()
        .expect("verification runs");
    assert!(!report.success());
    let reports: Vec<_> = report.corruption_reports().collect();
    assert_eq!(reports.len(), 1, "{:?}", report.diagnostics());
    assert_eq!(reports[0].class(), CorruptionClass::Content);
}

#[test]
fn missing_chain_file_fails_both_implementations() {
    if !python_oracle_available() {
        return;
    }
    // A broken parent link is the same semantic failure in both
    // implementations.
    let store = tempfile::tempdir().expect("create temp store");
    let generation = Generator::builder(store.path())
        .max_files(3)
        .file_sizes(SizeChooser::fixed(512))
        .build()
        .generate()
        .expect("generation succeeds");
    let tip_bytes =
        fs::read(hash_to_path(store.path(), generation.chain_tip())).expect("the tip exists");
    let victim = Header::parse(&tip_bytes).expect("valid header").parent();
    fs::remove_file(hash_to_path(store.path(), victim)).expect("delete the mid-chain file");

    let python = python_verify(store.path());
    assert_eq!(python.status.code(), Some(1), "Python must fail");

    let report = Verifier::new(store.path())
        .verify()
        .expect("verification runs");
    assert!(!report.success());
    assert!(
        report.diagnostics().iter().any(|diagnostic| matches!(
            diagnostic,
            Diagnostic::MissingParent { parent, .. } if *parent == victim
        )),
        "{:?}",
        report.diagnostics()
    );
}

/// What a placed chain file carries in its reserved header field.
#[derive(Clone, Copy)]
enum Reserved {
    /// The zeros a valid v2 header has.
    Zero,
    /// A poked byte, which the header checksum does not cover.
    Poked(u8),
}

/// Builds a self-consistent chain file, places it at its digest path,
/// and returns the digest.
fn place_chain_file(
    store: &Path,
    parent: Digest,
    seed: ContentSeed,
    file_length: u64,
    reserved: Reserved,
) -> Digest {
    let header = Header::new(parent, seed, file_length).expect("length is legal");
    let mut bytes = header.encode().to_vec();
    if let Reserved::Poked(value) = reserved {
        bytes[55] = value; // Reserved range; not covered by the checksum.
    }
    let content_length = usize::try_from(file_length).expect("test sizes are small") - HEADER_SIZE;
    let mut content = vec![0_u8; content_length];
    ContentReader::new(seed)
        .read_exact(&mut content)
        .expect("the content stream is infinite");
    bytes.extend_from_slice(&content);
    let digest = Digest::compute(&bytes);
    let path = hash_to_path(store, digest);
    fs::create_dir_all(path.parent().expect("hash paths have parents"))
        .expect("create shard directories");
    fs::write(&path, &bytes).expect("write the file");
    digest
}

/// Writes `.metadata/roots` markers and a matching `.metadata/all`.
fn write_roots_metadata(store: &Path, tips: &[Digest]) {
    let roots_dir = store.join(".metadata").join("roots");
    fs::create_dir_all(&roots_dir).expect("create the roots directory");
    let mut names: Vec<String> = tips.iter().map(Digest::to_hex).collect();
    names.sort_unstable();
    let mut hasher = Hasher::new();
    for name in &names {
        fs::File::create(roots_dir.join(name)).expect("create a marker");
        hasher.update(name.as_bytes());
    }
    fs::write(
        store.join(".metadata").join("all"),
        hasher.finalize().to_hex(),
    )
    .expect("write the aggregate");
}

#[test]
fn reserved_byte_asymmetry_is_pinned() {
    if !python_oracle_available() {
        return;
    }
    // A self-consistent file with nonzero reserved bytes
    // passes Python `verify` (the reserved field is unchecked there)
    // but fails the Rust verifier as an invalid v2 header. This is the
    // documented compatibility asymmetry.
    let store = tempfile::tempdir().expect("create temp store");
    let seed = ContentSeed::from_bytes(*b"differential-d1!");
    let header = Header::new(Digest::ZERO, seed, 1024).expect("length is legal");
    let mut bytes = header.encode().to_vec();
    bytes[55] = 0xFF; // Reserved range; not covered by the checksum.
    let mut content = vec![0_u8; 1024 - HEADER_SIZE];
    ContentReader::new(seed)
        .read_exact(&mut content)
        .expect("the content stream is infinite");
    bytes.extend_from_slice(&content);
    let digest = Digest::compute(&bytes);
    let path = hash_to_path(store.path(), digest);
    fs::create_dir_all(path.parent().expect("hash paths have parents"))
        .expect("create shard directories");
    fs::write(&path, &bytes).expect("write the file");

    let roots_dir = store.path().join(".metadata").join("roots");
    fs::create_dir_all(&roots_dir).expect("create the roots directory");
    fs::File::create(roots_dir.join(digest.to_hex())).expect("create the marker");
    let mut hasher = Hasher::new();
    hasher.update(digest.to_hex().as_bytes());
    fs::write(
        store.path().join(".metadata").join("all"),
        hasher.finalize().to_hex(),
    )
    .expect("write the aggregate");

    let python = python_verify(store.path());
    assert!(
        python.status.success(),
        "Python accepts nonzero reserved bytes (frozen quirk)\nstderr:\n{}",
        String::from_utf8_lossy(&python.stderr),
    );

    let report = Verifier::new(store.path())
        .verify()
        .expect("verification runs");
    assert!(!report.success());
    assert!(
        report.diagnostics().iter().any(|diagnostic| matches!(
            diagnostic,
            Diagnostic::InvalidHeader { source, .. } if source.is_reserved_not_zero()
        )),
        "{:?}",
        report.diagnostics()
    );
}

#[test]
fn reserved_byte_orphan_cascade_is_pinned() {
    if !python_oracle_available() {
        return;
    }
    // A hand-crafted mid-chain file with
    // nonzero reserved bytes. Python never checks the reserved field,
    // so the chain verifies cleanly (exit 0). Rust rejects the file as
    // an invalid v2 header, which also hides its parent link, so the
    // parent cascades into a false orphan diagnostic. The pure-Rust
    // side is reserved_byte_mid_chain_file_cascades_to_a_false_orphan
    // in tests/verification.rs.
    let store = tempfile::tempdir().expect("create temp store");
    let parent = place_chain_file(
        store.path(),
        Digest::ZERO,
        ContentSeed::from_bytes(*b"cascade-parent!!"),
        512,
        Reserved::Zero,
    );
    let tip = place_chain_file(
        store.path(),
        parent,
        ContentSeed::from_bytes(*b"cascade-tip-file"),
        512,
        Reserved::Poked(0xFF),
    );
    write_roots_metadata(store.path(), &[tip]);

    let python = python_verify(store.path());
    assert!(
        python.status.success(),
        "Python accepts the reserved-byte chain (frozen quirk)\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&python.stdout),
        String::from_utf8_lossy(&python.stderr),
    );

    let report = Verifier::new(store.path())
        .verify()
        .expect("verification runs");
    assert!(!report.success());
    let [header, orphan] = report.diagnostics() else {
        panic!("exactly two diagnostics: {:?}", report.diagnostics());
    };
    assert!(
        matches!(
            header,
            Diagnostic::InvalidHeader { path, source }
                if path == &hash_to_path(store.path(), tip) && source.is_reserved_not_zero()
        ),
        "{header:?}"
    );
    assert!(
        matches!(
            orphan,
            Diagnostic::OrphanedFile { path }
                if path == &hash_to_path(store.path(), parent)
        ),
        "{orphan:?}"
    );
}

#[test]
fn reserved_byte_flip_in_a_genuine_file_diverges_in_class() {
    if !python_oracle_available() {
        return;
    }
    // Flipping a reserved byte of a genuine
    // Python-generated file fails both implementations (exit 1), but
    // the diagnosis differs. Python's header check passes (the
    // checksum covers bytes 0-43 only) and the whole-file digest no
    // longer matches the path with zero content bytes differing, so it
    // reports PATH MISMATCH (content valid); Rust rejects the header
    // outright.
    let store = tempfile::tempdir().expect("create temp store");
    python_generate(store.path(), 1, "1024");
    let file = only_data_file(store.path());
    let mut handle = OpenOptions::new()
        .write(true)
        .open(&file)
        .expect("data files are writable");
    handle.seek(SeekFrom::Start(55)).expect("seek succeeds");
    handle.write_all(&[0x01]).expect("write succeeds");
    drop(handle);

    let python = python_verify(store.path());
    assert_eq!(python.status.code(), Some(1), "Python must fail");
    assert!(
        String::from_utf8_lossy(&python.stdout).contains("PATH MISMATCH"),
        "Python classifies the flip as a path mismatch\nstdout:\n{}",
        String::from_utf8_lossy(&python.stdout),
    );

    let report = Verifier::new(store.path())
        .verify()
        .expect("verification runs");
    assert!(!report.success());
    let [diagnostic] = report.diagnostics() else {
        panic!("exactly one diagnostic: {:?}", report.diagnostics());
    };
    assert!(
        matches!(
            diagnostic,
            Diagnostic::InvalidHeader { path, source }
                if path == &file && source.is_reserved_not_zero()
        ),
        "{diagnostic:?}"
    );
}
