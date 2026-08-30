//! Store-level integration tests for one-chain generation.
//!
//! Every test generates into a temporary store and re-validates the
//! result with `caf-format` primitives: path layout, header fields,
//! version-specific file identities, deterministic content, chain links, chain-tip
//! markers, and the `.metadata/all` aggregate.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read as _;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use caf_format::{
    BLOCK_SIZE, ContentReader, Digest, FileId, Format, HEADER_SIZE, Hasher, Header,
    parse_hash_from_path, v3_file_id_from_bytes,
};
use caf_store::{Generator, SizeChooser, SizeSpec};

/// The pinned golden digest for a store whose only chain tip is the
/// all-zero marker. [`golden_zero_file_all_digest`] re-reads it from the
/// `zero-file-store` vector in `tests/golden/vectors.json`.
const ZERO_FILE_STORE_ALL: &str = "cf2fa9f42f4a05d4a32ce694d0d97a99dd7d97c1";

fn golden_zero_file_all_digest() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/vectors.json");
    let json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(path).expect("golden vectors exist"))
            .expect("golden vectors parse");
    let vector = json["metadata_vectors"]
        .as_array()
        .expect("metadata vectors are a list")
        .iter()
        .find(|vector| vector["name"] == "zero-file-store")
        .expect("the zero-file-store vector is pinned");
    vector["all_file_contents"]
        .as_str()
        .expect("all_file_contents is a string")
        .to_owned()
}

/// What one level of the walk leaves out.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Skip<'a> {
    /// Skip this directory: the store root's own `.metadata`.
    Path(&'a Path),
    /// Skip nothing, which is every level below the root.
    Nothing,
}

/// Returns every data file in the store (sorted absolute paths),
/// skipping the `.metadata` directory that is a direct child of the
/// root.
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
    out.sort();
    out
}

fn chain_tip_markers(root: &Path) -> Vec<String> {
    let roots_dir = root.join(".metadata").join("roots");
    let mut names: Vec<String> = fs::read_dir(&roots_dir)
        .expect("the roots directory exists")
        .map(|entry| {
            entry
                .expect("marker entries are readable")
                .file_name()
                .into_string()
                .expect("marker names are ASCII hex")
        })
        .collect();
    names.sort();
    names
}

fn all_file_contents(root: &Path) -> String {
    fs::read_to_string(root.join(".metadata").join("all")).expect("the all file exists")
}

/// Structurally verifies a generated store with `caf-format` primitives.
///
/// Checks every data file's path layout, header, length, whole-file
/// digest, and deterministic content; then walks each chain tip back to
/// the zero parent and requires the chains to cover every data file
/// exactly once; then recomputes the `.metadata/all` aggregate.
fn check_store(root: &Path) {
    let mut parents: HashMap<Digest, Digest> = HashMap::new();
    for path in data_files(root) {
        let digest = parse_hash_from_path(&path)
            .unwrap_or_else(|err| panic!("{} is not in the CAF layout: {err}", path.display()));

        let bytes = fs::read(&path).expect("data files are readable");
        let header = Header::parse(&bytes)
            .unwrap_or_else(|err| panic!("{}: invalid header: {err}", path.display()));
        assert_eq!(
            header.file_length(),
            bytes.len() as u64,
            "{}: header length must match the file",
            path.display(),
        );
        let actual_id = match header.format() {
            Format::V2 => Digest::compute(&bytes),
            Format::V3 => Digest::from_bytes(v3_file_id_from_bytes(&bytes).into_inner()),
        };
        assert_eq!(
            actual_id,
            digest,
            "{}: file ID must match the path",
            path.display()
        );

        let mut expected = vec![0_u8; bytes.len() - HEADER_SIZE];
        ContentReader::new_with_format(header.content_seed(), header.format())
            .read_exact(&mut expected)
            .expect("the content stream is infinite");
        assert_eq!(
            expected,
            bytes[HEADER_SIZE..],
            "{}: content must be the deterministic stream",
            path.display(),
        );

        let previous = parents.insert(digest, header.parent());
        assert!(previous.is_none(), "duplicate digest {digest}");
    }

    let mut visited: HashSet<Digest> = HashSet::new();
    for marker in chain_tip_markers(root) {
        let mut cursor = Digest::from_hex(&marker).expect("markers are hex digests");
        while !cursor.is_zero() {
            assert!(visited.insert(cursor), "{cursor} is in two chains");
            let parent = parents
                .get(&cursor)
                .unwrap_or_else(|| panic!("chain link {cursor} has no data file"));
            cursor = *parent;
        }
    }
    assert_eq!(
        visited.len(),
        parents.len(),
        "every data file must be reachable from a chain tip"
    );

    let mut hasher = Hasher::new();
    for marker in chain_tip_markers(root) {
        hasher.update(marker.as_bytes());
    }
    assert_eq!(
        all_file_contents(root),
        hasher.finalize().to_hex(),
        ".metadata/all must aggregate the sorted marker names"
    );
}

#[test]
fn three_file_chain_is_structurally_valid() {
    let store = tempfile::tempdir().expect("create temp store");
    let report = Generator::builder(store.path())
        .max_files(3)
        .file_sizes(SizeChooser::fixed(1024))
        .build()
        .generate()
        .expect("generation succeeds");

    assert_eq!(report.files_created(), 3);
    assert_eq!(report.bytes_written(), 3 * 1024);
    assert_eq!(report.format(), Format::V3);
    assert!(report.chain_tip_file_id().is_some());
    assert_eq!(data_files(store.path()).len(), 3);
    for path in data_files(store.path()) {
        let bytes = fs::read(path).expect("generated files are readable");
        assert_eq!(
            Header::parse(bytes).expect("valid header").format(),
            Format::V3
        );
    }
    assert_eq!(
        chain_tip_markers(store.path()),
        vec![report.chain_tip().to_hex()]
    );
    assert_eq!(
        all_file_contents(store.path()),
        report.all_digest().to_hex()
    );
    check_store(store.path());
}

#[test]
fn explicit_v2_generation_remains_available() {
    let store = tempfile::tempdir().expect("create temp store");
    let report = Generator::builder(store.path())
        .format(Format::V2)
        .max_files(2)
        .file_sizes(SizeChooser::fixed(1024))
        .build()
        .generate()
        .expect("v2 generation succeeds");

    assert_eq!(report.format(), Format::V2);
    assert_eq!(report.chain_tip_file_id(), None);

    for path in data_files(store.path()) {
        let bytes = fs::read(path).expect("generated files are readable");
        assert_eq!(
            Header::parse(bytes).expect("valid header").format(),
            Format::V2
        );
    }
    check_store(store.path());
}

#[test]
fn parallel_generation_produces_a_structurally_valid_store() {
    // Eight 1 MiB blocks over four workers clears the two-blocks-per-
    // worker threshold, so this run takes the parallel path on a real
    // filesystem. The store it writes has to satisfy every rule a
    // serially generated one does, down to the deterministic content.
    let store = tempfile::tempdir().expect("create temp store");
    let file_size = 8 * BLOCK_SIZE as u64;
    let report = Generator::builder(store.path())
        .max_files(2)
        .file_sizes(SizeChooser::fixed(file_size))
        .jobs(NonZeroUsize::new(4).expect("four workers"))
        .build()
        .generate()
        .expect("generation succeeds");

    assert_eq!(report.files_created(), 2);
    assert_eq!(report.bytes_written(), 2 * file_size);
    for path in data_files(store.path()) {
        assert_eq!(
            fs::metadata(&path).expect("data files exist").len(),
            file_size,
        );
    }
    check_store(store.path());
}

#[test]
fn parallel_generation_reports_exact_monotonic_progress() {
    let store = tempfile::tempdir().expect("create temp store");
    let file_size = 8 * BLOCK_SIZE as u64;
    let snapshots = Arc::new(Mutex::new(Vec::new()));
    let reported = Arc::clone(&snapshots);

    Generator::builder(store.path())
        .max_files(2)
        .file_sizes(SizeChooser::fixed(file_size))
        .jobs(NonZeroUsize::new(4).expect("four workers"))
        .progress(move |snapshot| {
            reported.lock().expect("progress log").push(snapshot);
        })
        .build()
        .generate()
        .expect("generation succeeds");

    let snapshots = snapshots.lock().expect("progress log");
    let first = snapshots.first().expect("an initial snapshot");
    assert_eq!(first.bytes_completed(), 0);
    assert_eq!(first.files_completed(), 0);
    assert_eq!(first.total_bytes(), Some(2 * file_size));
    assert_eq!(first.total_files(), Some(2));
    let last = snapshots.last().expect("a final snapshot");
    assert_eq!(last.bytes_completed(), 2 * file_size);
    assert_eq!(last.files_completed(), 2);
    assert!(
        snapshots.len() > 4,
        "large files report block-level updates"
    );
    assert!(snapshots.windows(2).all(|pair| {
        pair[0].bytes_completed() <= pair[1].bytes_completed()
            && pair[0].files_completed() <= pair[1].files_completed()
    }));
}

#[test]
fn zero_files_writes_the_zero_chain_tip() {
    // --max-files 0 still writes the all-zero chain tip and
    // a verifiable store; the aggregate is pinned as a golden vector.
    let store = tempfile::tempdir().expect("create temp store");
    let report = Generator::builder(store.path())
        .max_files(0)
        .build()
        .generate()
        .expect("generation succeeds");

    assert_eq!(report.files_created(), 0);
    assert_eq!(report.bytes_written(), 0);
    assert_eq!(report.format(), Format::V3);
    assert_eq!(report.chain_tip(), Digest::ZERO);
    assert_eq!(report.chain_tip_file_id(), Some(FileId::ZERO));
    assert!(data_files(store.path()).is_empty());
    assert_eq!(chain_tip_markers(store.path()), vec!["0".repeat(40)]);

    let golden = golden_zero_file_all_digest();
    assert_eq!(golden, ZERO_FILE_STORE_ALL);
    assert_eq!(all_file_contents(store.path()), golden);
    check_store(store.path());
}

#[test]
fn disk_budget_is_checked_before_each_file() {
    // A budget of 10,000 with 4,096-byte files stops after three files
    // (12,288 bytes), so the final file overshoots.
    let store = tempfile::tempdir().expect("create temp store");
    let report = Generator::builder(store.path())
        .max_disk_usage(10_000)
        .file_sizes(SizeChooser::fixed(4096))
        .build()
        .generate()
        .expect("generation succeeds");

    assert_eq!(report.files_created(), 3);
    assert_eq!(report.bytes_written(), 12_288);
    let sizes: u64 = data_files(store.path())
        .iter()
        .map(|path| fs::metadata(path).expect("data files exist").len())
        .sum();
    assert_eq!(sizes, 12_288);
    check_store(store.path());
}

#[test]
fn both_limits_stop_at_whichever_hits_first() {
    let store = tempfile::tempdir().expect("create temp store");
    let report = Generator::builder(store.path())
        .max_files(2)
        .max_disk_usage(1 << 30)
        .file_sizes(SizeChooser::fixed(4096))
        .build()
        .generate()
        .expect("generation succeeds");
    assert_eq!(report.files_created(), 2);
    check_store(store.path());
}

#[test]
fn sizes_below_the_header_are_clamped_to_60() {
    // Any requested size below 60 bytes is
    // silently clamped to the header size.
    let store = tempfile::tempdir().expect("create temp store");
    let mut requests = [0_u64, 1, 59, 60].into_iter();
    let report = Generator::builder(store.path())
        .max_files(4)
        .file_sizes(SizeChooser::from_fn(move || {
            requests.next().expect("exactly four files are requested")
        }))
        .build()
        .generate()
        .expect("generation succeeds");

    assert_eq!(report.bytes_written(), 4 * 60);
    for path in data_files(store.path()) {
        assert_eq!(fs::metadata(&path).expect("data files exist").len(), 60);
    }
    check_store(store.path());
}

#[test]
fn layout_uses_three_shards_and_a_34_char_basename() {
    let store = tempfile::tempdir().expect("create temp store");
    Generator::builder(store.path())
        .max_files(1)
        .file_sizes(SizeChooser::fixed(1024))
        .build()
        .generate()
        .expect("generation succeeds");

    let [path] = &*data_files(store.path()) else {
        panic!("exactly one data file is generated");
    };
    let relative = path
        .strip_prefix(store.path())
        .expect("data files live under the store root");
    let parts: Vec<&str> = relative
        .iter()
        .map(|part| part.to_str().expect("generated names are ASCII hex"))
        .collect();
    assert_eq!(parts.len(), 4, "{relative:?}");
    for shard in &parts[..3] {
        assert_eq!(shard.len(), 2);
        assert!(
            shard
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
    }
    assert_eq!(parts[3].len(), 34);
    assert!(
        parts[3]
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    );
}

#[test]
fn multi_block_files_carry_the_deterministic_stream() {
    // One file straddling the 1 MiB block boundary: block 0 is shortened
    // by the header, so this file uses blocks 0 and 1.
    let store = tempfile::tempdir().expect("create temp store");
    let size = BLOCK_SIZE as u64 + 4096;
    let report = Generator::builder(store.path())
        .max_files(1)
        .file_sizes(SizeChooser::fixed(size))
        .build()
        .generate()
        .expect("generation succeeds");
    assert_eq!(report.bytes_written(), size);
    check_store(store.path());
}

#[test]
fn successive_runs_append_chains_and_update_the_aggregate() {
    let store = tempfile::tempdir().expect("create temp store");
    let first = Generator::builder(store.path())
        .max_files(2)
        .file_sizes(SizeChooser::fixed(512))
        .build()
        .generate()
        .expect("first run succeeds");
    let second = Generator::builder(store.path())
        .max_files(3)
        .file_sizes(SizeChooser::fixed(512))
        .build()
        .generate()
        .expect("second run succeeds");

    assert_eq!(data_files(store.path()).len(), 5);
    let mut expected_markers = vec![first.chain_tip().to_hex(), second.chain_tip().to_hex()];
    expected_markers.sort();
    assert_eq!(chain_tip_markers(store.path()), expected_markers);
    assert_eq!(
        all_file_contents(store.path()),
        second.all_digest().to_hex()
    );
    check_store(store.path());
}

#[test]
fn no_temporary_files_remain_after_generation() {
    let store = tempfile::tempdir().expect("create temp store");
    Generator::builder(store.path())
        .max_files(20)
        .file_sizes(SizeChooser::fixed(256))
        .build()
        .generate()
        .expect("generation succeeds");

    // The store root may contain only two-character shard directories
    // and `.metadata`; a leftover temporary would sit directly in the
    // root (and `check_store` would reject it as outside the layout).
    for entry in fs::read_dir(store.path()).expect("store root is readable") {
        let entry = entry.expect("entries are readable");
        let name = entry.file_name();
        let name = name.to_str().expect("generated names are ASCII");
        assert!(
            name == ".metadata" || (name.len() == 2 && entry.path().is_dir()),
            "unexpected entry {name:?} in the store root",
        );
    }
    check_store(store.path());
}

#[test]
fn every_size_mode_produces_a_structurally_valid_store() {
    // Each size-selection mode must produce a structurally valid store.
    let modes = [
        "4096",
        "60",
        "1kb-2kb",
        "60-60",
        "Type=normal,Mean=2kb,StdDev=1kb",
        "Type=gamma,Alpha=2,Beta=1kb",
        "Type=lognormal,Mean=8,StdDev=1",
    ];
    for mode in modes {
        let store = tempfile::tempdir().expect("create temp store");
        let spec: SizeSpec = mode.parse().unwrap_or_else(|err| panic!("{mode}: {err}"));
        let report = Generator::builder(store.path())
            .max_files(5)
            .file_sizes(spec.chooser().unwrap_or_else(|err| panic!("{mode}: {err}")))
            .build()
            .generate()
            .unwrap_or_else(|err| panic!("{mode}: {err}"));
        assert_eq!(report.files_created(), 5, "{mode}");
        check_store(store.path());
    }
}

#[test]
fn size_selection_failure_reports_before_writing_anything() {
    // A lognormal overflow surfaces as a structured error before any
    // file or metadata write.
    let store = tempfile::tempdir().expect("create temp store");
    let chooser = SizeSpec::lognormal(1e6, 0.0)
        .expect("the parameters are inside the sampler's domain")
        .chooser()
        .expect("construction parameters are valid");
    let err = Generator::builder(store.path())
        .max_files(1)
        .file_sizes(chooser)
        .build()
        .generate()
        .expect_err("the first sample overflows");

    assert!(err.is_size_selection());
    let leftovers: Vec<_> = fs::read_dir(store.path())
        .expect("store root is readable")
        .collect();
    assert!(
        leftovers.is_empty(),
        "nothing may be written: {leftovers:?}"
    );
}

#[cfg(unix)]
#[test]
fn interrupted_aggregate_replacement_leaves_the_old_all_intact() {
    use std::os::unix::fs::PermissionsExt as _;

    // The `.metadata/all` replacement goes through a
    // temporary file plus rename. Failing the replacement (read-only
    // `.metadata`) must leave the previous `all` byte-identical and no
    // temporary behind — never a partial file.
    let store = tempfile::tempdir().expect("create temp store");
    Generator::builder(store.path())
        .max_files(1)
        .file_sizes(SizeChooser::fixed(256))
        .build()
        .generate()
        .expect("first run succeeds");
    let before = all_file_contents(store.path());

    let metadata_dir = store.path().join(".metadata");
    let writable = fs::metadata(&metadata_dir)
        .expect("metadata dir exists")
        .permissions();
    fs::set_permissions(&metadata_dir, fs::Permissions::from_mode(0o555))
        .expect("make .metadata read-only");

    let err = Generator::builder(store.path())
        .max_files(1)
        .file_sizes(SizeChooser::fixed(256))
        .build()
        .generate()
        .expect_err("the aggregate replacement fails");
    fs::set_permissions(&metadata_dir, writable).expect("restore permissions");

    assert!(err.is_io());
    assert_eq!(all_file_contents(store.path()), before);
    let stray: Vec<_> = fs::read_dir(&metadata_dir)
        .expect("metadata dir is readable")
        .map(|entry| entry.expect("entries are readable").file_name())
        .filter(|name| name != "all" && name != "roots")
        .collect();
    assert!(stray.is_empty(), "no temporaries may remain: {stray:?}");
}
