//! Subprocess tests for the `caf` binary.
//!
//! Assertions cover exit status, sizes, and key output fields rather than
//! byte-for-byte terminal snapshots. Output is always captured (not a
//! terminal), so it must contain no ANSI escape sequences.

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

use assert_cmd::Command;

/// Exit status of `output`, panicking only on signal termination.
fn code(output: &Output) -> i32 {
    output
        .status
        .code()
        .expect("process exited without a signal")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Runs `caf` with `args` from an unrelated working directory.
fn caf<I, S>(args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut command = Command::cargo_bin("caf").expect("caf binary builds");
    command.args(args).output().expect("caf runs")
}

/// Runs `caf` with `args` from `dir` (for current-directory defaults).
fn caf_in<I, S>(dir: &Path, args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut command = Command::cargo_bin("caf").expect("caf binary builds");
    command
        .current_dir(dir)
        .args(args)
        .output()
        .expect("caf runs")
}

/// Runs `caf <before…> <path> [after…]`, passing `path` as it is: a
/// path argument never goes through `str`, so tests can use any path
/// the operating system accepts.
fn caf_with_path(before: &[&str], path: &Path, after: &[&str]) -> Output {
    let mut args: Vec<&OsStr> = before.iter().map(OsStr::new).collect();
    args.push(path.as_os_str());
    args.extend(after.iter().map(OsStr::new));
    caf(args)
}

/// Runs `caf gen --directory <store> [args…]`.
fn generate(store: &Path, args: &[&str]) -> Output {
    caf_with_path(&["gen", "--directory"], store, args)
}

/// Runs `caf verify --directory <store> [args…]`.
fn verify(store: &Path, args: &[&str]) -> Output {
    caf_with_path(&["verify", "--directory"], store, args)
}

/// Every data file in the store (skipping `.metadata`), sorted.
fn data_files(root: &Path) -> Vec<PathBuf> {
    fn walk(dir: &Path, files: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(dir).expect("store directory is readable") {
            let entry = entry.expect("directory entry is readable");
            let path = entry.path();
            if path.is_dir() {
                if entry.file_name() != ".metadata" {
                    walk(&path, files);
                }
            } else {
                files.push(path);
            }
        }
    }
    let mut files = Vec::new();
    walk(root, &mut files);
    files.sort();
    files
}

fn sizes_of(files: &[PathBuf]) -> Vec<u64> {
    files
        .iter()
        .map(|path| fs::metadata(path).expect("data file exists").len())
        .collect()
}

fn tempdir() -> tempfile::TempDir {
    tempfile::tempdir().expect("temporary directory is creatable")
}

/// A generated store plus its (sorted) data files.
fn store_with(args: &[&str]) -> (tempfile::TempDir, Vec<PathBuf>) {
    let dir = tempdir();
    let output = generate(dir.path(), args);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    let files = data_files(dir.path());
    (dir, files)
}

// --- version, help, and usage errors ----------------------------------

#[test]
fn version_reporting() {
    let output = caf(["--version"]);
    assert_eq!(code(&output), 0);
    assert!(
        stdout(&output).starts_with("caf, version "),
        "{}",
        stdout(&output)
    );
}

#[test]
fn help_lists_the_frozen_commands() {
    let output = caf(["--help"]);
    assert_eq!(code(&output), 0);
    let help = stdout(&output);
    for command in ["gen", "verify", "dev"] {
        assert!(help.contains(command), "missing {command}: {help}");
    }
}

#[test]
fn bare_invocation_is_a_usage_error() {
    // `caf` with no arguments prints help and exits 2.
    let output = caf::<[&str; 0], _>([]);
    assert_eq!(code(&output), 2);
}

#[test]
fn unknown_command_is_usage_error() {
    assert_eq!(code(&caf(["not-a-command"])), 2);
}

#[test]
fn invalid_file_size_spec_is_usage_error() {
    let dir = tempdir();
    assert_eq!(code(&generate(dir.path(), &["--file-size", "bogus"])), 2);
}

#[test]
fn invalid_range_spec_is_usage_error() {
    let dir = tempdir();
    assert_eq!(
        code(&generate(dir.path(), &["--file-size", "1mb-2mb-3mb"])),
        2
    );
}

#[test]
fn shorthand_missing_type_is_usage_error() {
    let dir = tempdir();
    assert_eq!(
        code(&generate(dir.path(), &["--file-size", "Mean=1,StdDev=1"])),
        2
    );
}

#[test]
fn shorthand_unknown_type_is_usage_error() {
    let dir = tempdir();
    assert_eq!(
        code(&generate(dir.path(), &["--file-size", "Type=zipf,Mean=1"])),
        2
    );
}

#[test]
fn shorthand_unknown_parameter_is_usage_error() {
    // Parameter names are validated at parse time (exit 2) instead of
    // crashing during generation.
    let dir = tempdir();
    let spec = "Type=normal,Mean=1kb,StdDev=0,Foo=2";
    assert_eq!(code(&generate(dir.path(), &["--file-size", spec])), 2);
}

#[test]
fn invalid_max_disk_usage_is_usage_error() {
    let dir = tempdir();
    assert_eq!(code(&generate(dir.path(), &["--max-disk-usage", "1xy"])), 2);
}

#[test]
fn empty_range_is_usage_error() {
    let dir = tempdir();
    assert_eq!(code(&generate(dir.path(), &["--file-size", "2kb-1kb"])), 2);
}

// --- gen defaults and size grammar ------------------------------------

#[test]
fn gen_default_is_100_files_of_4096_bytes() {
    let (_dir, files) = store_with(&[]);
    let sizes = sizes_of(&files);
    assert_eq!(sizes.len(), 100);
    assert!(sizes.iter().all(|&size| size == 4096), "{sizes:?}");
}

#[test]
fn file_size_suffix_grammar() {
    for (spec, expected) in [
        ("8192", 8192),
        ("2kb", 2 * 1024),
        ("2KB", 2 * 1024),
        ("2Kb", 2 * 1024),
        ("1mb", 1024 * 1024),
        ("1MB", 1024 * 1024),
    ] {
        let (_dir, files) = store_with(&["--max-files", "1", "--file-size", spec]);
        assert_eq!(sizes_of(&files), vec![expected], "{spec}");
    }
}

#[test]
fn max_disk_usage_large_suffixes_parse() {
    // Exercises gb/tb parsing without generating huge files: one small
    // file never reaches the budget.
    for suffix in ["1gb", "1tb", "1GB", "1TB"] {
        let (_dir, files) = store_with(&[
            "--max-files",
            "1",
            "--file-size",
            "60",
            "--max-disk-usage",
            suffix,
        ]);
        assert_eq!(files.len(), 1, "{suffix}");
    }
}

#[test]
fn file_size_range_is_inclusive() {
    // A degenerate range pins both endpoints: 60-60 always yields 60.
    let (_dir, files) = store_with(&["--max-files", "3", "--file-size", "60-60"]);
    assert_eq!(sizes_of(&files), vec![60, 60, 60]);
}

#[test]
fn file_size_range_samples_stay_inside_the_bounds() {
    let (_dir, files) = store_with(&["--max-files", "5", "--file-size", "4048-8096"]);
    let sizes = sizes_of(&files);
    assert_eq!(sizes.len(), 5);
    assert!(
        sizes.iter().all(|size| (4048..=8096).contains(size)),
        "{sizes:?}"
    );
}

#[test]
fn file_size_below_header_is_clamped_to_60() {
    let (_dir, files) = store_with(&["--max-files", "1", "--file-size", "0"]);
    assert_eq!(sizes_of(&files), vec![60]);
}

// --- distribution grammar ---------------------------------------------

#[test]
fn normal_distribution_grammar() {
    // StdDev=0 makes the sample deterministic: exactly Mean.
    let (_dir, files) = store_with(&[
        "--max-files",
        "2",
        "--file-size",
        "Type=normal,Mean=1kb,StdDev=0",
    ]);
    assert_eq!(sizes_of(&files), vec![1024, 1024]);
}

#[test]
fn lognormal_distribution_grammar_is_log_space() {
    // Mean and StdDev are log-space parameters, so StdDev=0
    // gives int(e^8) == 2980 bytes, not 8 bytes.
    let (_dir, files) = store_with(&[
        "--max-files",
        "1",
        "--file-size",
        "Type=lognormal,Mean=8,StdDev=0",
    ]);
    assert_eq!(sizes_of(&files), vec![2980]);
}

#[test]
fn gamma_distribution_grammar() {
    let (_dir, files) = store_with(&[
        "--max-files",
        "2",
        "--file-size",
        "Type=gamma,Alpha=2,Beta=1kb",
    ]);
    let sizes = sizes_of(&files);
    assert_eq!(sizes.len(), 2);
    assert!(sizes.iter().all(|&size| size >= 60), "{sizes:?}");
}

// --- stopping conditions ----------------------------------------------

#[test]
fn max_disk_usage_checked_before_each_file() {
    // The budget is checked before each file, so the final
    // file may overshoot it: 4096, 8192, 12288 -> stop.
    let (_dir, files) = store_with(&["--max-disk-usage", "10000", "--file-size", "4096"]);
    let sizes = sizes_of(&files);
    assert_eq!(sizes.len(), 3);
    assert_eq!(sizes.iter().sum::<u64>(), 12288);
}

#[test]
fn max_disk_usage_alone_is_the_only_stop() {
    let (_dir, files) = store_with(&["--max-disk-usage", "16384"]);
    assert_eq!(sizes_of(&files).iter().sum::<u64>(), 16384);
}

#[test]
fn max_disk_usage_mb_suffix() {
    let (_dir, files) = store_with(&["--max-disk-usage", "1MB"]);
    assert_eq!(sizes_of(&files).iter().sum::<u64>(), 1024 * 1024);
}

#[test]
fn max_files_wins_when_it_comes_first() {
    let (_dir, files) = store_with(&["--max-disk-usage", "16384", "--max-files", "2"]);
    assert_eq!(files.len(), 2);
}

#[test]
fn gen_zero_files_writes_zero_chain_tip() {
    // The all-zero digest becomes a chain tip and the
    // empty store verifies cleanly.
    let dir = tempdir();
    let output = generate(dir.path(), &["--max-files", "0"]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert_eq!(data_files(dir.path()), Vec::<PathBuf>::new());

    let roots: Vec<_> = fs::read_dir(dir.path().join(".metadata").join("roots"))
        .expect("roots directory exists")
        .map(|entry| entry.expect("entry is readable").file_name())
        .collect();
    assert_eq!(roots, vec![std::ffi::OsString::from("0".repeat(40))]);
    assert_eq!(code(&verify(dir.path(), &[])), 0);
}

#[test]
fn negative_max_files_behaves_like_zero() {
    // Negative counts generate no files.
    let dir = tempdir();
    let output = generate(dir.path(), &["--max-files", "-5"]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert_eq!(data_files(dir.path()), Vec::<PathBuf>::new());
}

#[test]
fn gen_creates_missing_directory() {
    let dir = tempdir();
    let target = dir.path().join("nested").join("store");
    let output = generate(&target, &["--max-files", "1"]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert_eq!(data_files(&target).len(), 1);
}

// --- verify -----------------------------------------------------------

#[test]
fn verify_success_with_cwd_default() {
    let (dir, files) = store_with(&[]);
    assert_eq!(files.len(), 100);
    // Without --directory, the current directory is the store.
    let output = caf_in(dir.path(), ["verify"]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(stdout(&output).contains("successfully verified"));
}

#[test]
fn verify_failure_after_deleting_a_file() {
    let (dir, files) = store_with(&[]);
    fs::remove_file(&files[42]).expect("data file is removable");
    let output = caf_in(dir.path(), ["verify"]);
    assert_eq!(code(&output), 1);
    assert!(stdout(&output).contains("Verification failed"));
}

#[test]
fn verify_non_store_directory_fails() {
    let dir = tempdir();
    let output = verify(dir.path(), &[]);
    assert_eq!(code(&output), 1);
    assert!(
        stderr(&output).contains("not a valid CAF store"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn verify_reports_analysis_chunk_size() {
    let (dir, _files) = store_with(&["--max-files", "1"]);
    let output = verify(dir.path(), &["--chunk-size", "512"]);
    assert_eq!(code(&output), 0);
    assert!(stdout(&output).contains("512 bytes"), "{}", stdout(&output));
}

#[test]
fn verify_chunk_sizes_are_reported_with_separators() {
    let (dir, _files) = store_with(&["--max-files", "1", "--file-size", "2048"]);
    for (chunk_size, reported) in [("256", "256"), ("1024", "1,024"), ("2048", "2,048")] {
        let output = verify(dir.path(), &["--chunk-size", chunk_size]);
        assert_eq!(code(&output), 0);
        assert!(
            stdout(&output).contains(&format!("{reported} bytes")),
            "{chunk_size}: {}",
            stdout(&output)
        );
    }
}

#[test]
fn verify_detects_content_corruption() {
    use std::io::{Seek as _, SeekFrom, Write as _};

    let (dir, files) = store_with(&["--max-files", "1", "--file-size", "2048"]);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .open(&files[0])
        .expect("data file is writable");
    file.seek(SeekFrom::Start(200)).expect("seek succeeds");
    file.write_all(&[0xFF; 1000]).expect("write succeeds");
    drop(file);

    let output = verify(dir.path(), &[]);
    assert_eq!(code(&output), 1);
    assert!(
        stderr(&output).contains("CORRUPTION"),
        "{}",
        stderr(&output)
    );
    let report = stdout(&output);
    for field in [
        "Error Analysis",
        "CONTENT CORRUPTED",
        "Expected BLAKE2b",
        "Actual BLAKE2b",
        "Content Seed:",
        "Corruption Analysis",
        "Region 1:",
        "Pattern:",
        "Visualization:",
    ] {
        assert!(report.contains(field), "missing {field:?}: {report}");
    }
    // Captured output is not a terminal: no ANSI escapes anywhere.
    assert!(!report.contains('\u{1b}'), "{report}");
    assert!(!stderr(&output).contains('\u{1b}'), "{}", stderr(&output));
}

#[test]
fn verify_classifies_a_wrong_path_copy_as_path_mismatch() {
    let (dir, files) = store_with(&["--max-files", "2", "--file-size", "1024"]);
    // Copy a valid file to a wrong-but-well-formed store path: content
    // stays valid, so the report class is PATH MISMATCH, and nothing
    // references the copy, so it is also an orphan.
    let source = &files[0];
    let mut basename = source
        .file_name()
        .and_then(|name| name.to_str())
        .expect("data files have hex basenames")
        .to_owned();
    basename.replace_range(0..1, if basename.starts_with('0') { "1" } else { "0" });
    let copy = source.with_file_name(basename);
    fs::copy(source, &copy).expect("data file is copyable");

    let output = verify(dir.path(), &[]);
    assert_eq!(code(&output), 1);
    let report = stdout(&output);
    assert!(
        report.contains("PATH MISMATCH") && report.contains("(content valid)"),
        "{report}"
    );
    assert!(
        report.contains("The file content is valid but stored at an incorrect path."),
        "{report}"
    );
    assert!(stderr(&output).contains("ORPHAN:"), "{}", stderr(&output));
}

#[test]
fn verify_reports_truncation_and_size_mismatch() {
    let (dir, files) = store_with(&["--max-files", "1", "--file-size", "4096"]);
    let content = fs::read(&files[0]).expect("data file is readable");
    fs::write(&files[0], &content[..1024]).expect("data file is writable");

    let output = verify(dir.path(), &[]);
    assert_eq!(code(&output), 1);
    assert!(
        stderr(&output).contains("File size mismatch"),
        "{}",
        stderr(&output)
    );
    let report = stdout(&output);
    assert!(report.contains("truncated"), "{report}");
    assert!(
        report.contains("Missing 3,072 bytes at end of file"),
        "{report}"
    );
}

#[test]
fn verify_reports_a_missing_root_marker_as_orphan_and_bad_roots() {
    let (dir, _files) = store_with(&["--max-files", "1", "--file-size", "1024"]);
    let roots = dir.path().join(".metadata").join("roots");
    for entry in fs::read_dir(&roots).expect("roots directory exists") {
        fs::remove_file(entry.expect("entry is readable").path()).expect("marker is removable");
    }

    let output = verify(dir.path(), &[]);
    assert_eq!(code(&output), 1);
    let diagnostics = stderr(&output);
    assert!(diagnostics.contains("ORPHAN:"), "{diagnostics}");
    assert!(
        diagnostics.contains("Root hash is not valid"),
        "{diagnostics}"
    );
}

#[test]
fn verify_jobs_matches_serial_output_exactly() {
    use std::io::{Seek as _, SeekFrom, Write as _};

    // Parallel verification produces the same report as a serial run.
    let (dir, files) = store_with(&["--max-files", "8", "--file-size", "1024"]);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .open(&files[3])
        .expect("data file is writable");
    file.seek(SeekFrom::Start(100)).expect("seek succeeds");
    file.write_all(&[0xAB; 64]).expect("write succeeds");
    drop(file);

    let serial = verify(dir.path(), &[]);
    let parallel = verify(dir.path(), &["--jobs", "4"]);
    assert_eq!(code(&serial), 1);
    assert_eq!(code(&parallel), 1);
    assert_eq!(stdout(&serial), stdout(&parallel));
    assert_eq!(stderr(&serial), stderr(&parallel));
}

#[test]
fn verify_jobs_below_one_is_usage_error() {
    // `--jobs` rejects values below one as usage errors.
    let dir = tempdir();
    assert_eq!(code(&verify(dir.path(), &["--jobs", "0"])), 2);
    assert_eq!(code(&verify(dir.path(), &["--jobs", "-1"])), 2);
}

#[test]
fn verify_chunk_size_below_one_is_usage_error() {
    // `--chunk-size` rejects values below one.
    let dir = tempdir();
    assert_eq!(code(&verify(dir.path(), &["--chunk-size", "0"])), 2);
    assert_eq!(code(&verify(dir.path(), &["--chunk-size", "-1"])), 2);
}

// --- dev show ---------------------------------------------------------

#[test]
fn dev_show_missing_file_is_usage_error() {
    assert_eq!(code(&caf(["dev", "show", "/nonexistent"])), 2);
}

#[test]
fn dev_show_directory_is_usage_error() {
    let dir = tempdir();
    assert_eq!(code(&caf_with_path(&["dev", "show"], dir.path(), &[])), 2);
}

#[test]
fn dev_show_prints_header_info() {
    let (_dir, files) = store_with(&["--max-files", "1", "--file-size", "1024"]);
    let output = caf_with_path(&["dev", "show"], &files[0], &[]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));

    let report = stdout(&output);
    for field in [
        "CAF header",
        "Parent Hash",
        "Content Seed",
        "File Length",
        "Header Checksum",
        "Reserved",
        "Basic validation:",
    ] {
        assert!(report.contains(field), "missing {field:?}: {report}");
    }
    assert!(!report.contains("File checksum"), "{report}");
}

#[test]
fn dev_show_small_file_is_an_error() {
    let dir = tempdir();
    let path = dir.path().join("tiny.bin");
    fs::write(&path, b"tiny").expect("test file is writable");
    let output = caf_with_path(&["dev", "show"], &path, &[]);
    assert_eq!(code(&output), 1);
    assert!(
        stderr(&output).contains("too small to be a CAF file"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn dev_show_without_flag_exits_zero_even_for_invalid_headers() {
    use std::io::{Seek as _, SeekFrom, Write as _};

    // Without --verify-checksum, dev show is
    // diagnostics only and always exits 0.
    let (_dir, files) = store_with(&["--max-files", "1", "--file-size", "1024"]);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .open(&files[0])
        .expect("data file is writable");
    file.seek(SeekFrom::Start(5)).expect("seek succeeds");
    file.write_all(&[0xFF]).expect("write succeeds");
    drop(file);

    let output = caf_with_path(&["dev", "show"], &files[0], &[]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(stdout(&output).contains("Valid: no"), "{}", stdout(&output));
}

#[test]
fn dev_show_verify_checksum_succeeds_for_clean_file() {
    let (_dir, files) = store_with(&["--max-files", "1", "--file-size", "1024"]);
    let output = caf_with_path(&["dev", "show"], &files[0], &["--verify-checksum"]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    let report = stdout(&output);
    assert!(report.contains("File checksum (BLAKE2b-160):"), "{report}");
    assert!(report.contains("Matches: yes"), "{report}");
}

#[test]
fn dev_show_verify_checksum_fails_for_corrupted_file() {
    use std::io::{Seek as _, SeekFrom, Write as _};

    let (_dir, files) = store_with(&["--max-files", "1", "--file-size", "1024"]);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .open(&files[0])
        .expect("data file is writable");
    file.seek(SeekFrom::Start(100)).expect("seek succeeds");
    file.write_all(&[0xFF]).expect("write succeeds");
    drop(file);

    let output = caf_with_path(&["dev", "show"], &files[0], &["--verify-checksum"]);
    assert_eq!(code(&output), 1);
    assert!(
        stdout(&output).contains("Matches: no"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn dev_show_verify_checksum_fails_outside_caf_layout() {
    // A file outside the store layout has no expected hash; with
    // --verify-checksum that is a failure (exit 1).
    let (_dir, files) = store_with(&["--max-files", "1", "--file-size", "1024"]);
    let dir = tempdir();
    let outside = dir.path().join("copy.bin");
    fs::copy(&files[0], &outside).expect("data file is copyable");

    let output = caf_with_path(&["dev", "show"], &outside, &["--verify-checksum"]);
    assert_eq!(code(&output), 1);
    assert!(
        stdout(&output).contains("<unavailable: not in CAF layout>"),
        "{}",
        stdout(&output)
    );
}

// --- dev corrupt-file -------------------------------------------------

#[test]
fn dev_corrupt_file_missing_file_is_usage_error() {
    assert_eq!(code(&caf(["dev", "corrupt-file", "/nonexistent"])), 2);
}

#[test]
fn dev_corrupt_file_start_beyond_eof_is_usage_error() {
    let (_dir, files) = store_with(&["--max-files", "1"]);
    let output = caf_with_path(&["dev", "corrupt-file"], &files[0], &["--start", "99999"]);
    assert_eq!(code(&output), 2);
    assert!(
        stderr(&output).contains("beyond file size"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn dev_corrupt_file_zero_preset_breaks_verification() {
    let (dir, files) = store_with(&["--max-files", "1"]);
    let output = caf_with_path(
        &["dev", "corrupt-file"],
        &files[0],
        &["--preset", "zero", "--start", "100", "--length", "100"],
    );
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    let echoed = stdout(&output);
    assert!(echoed.contains("Preset: zero"), "{echoed}");
    assert!(
        echoed.contains("Range: bytes 100 to 199 (100 bytes)"),
        "{echoed}"
    );
    assert!(echoed.contains("Corruption complete."), "{echoed}");
    assert_eq!(code(&verify(dir.path(), &[])), 1);
}

#[test]
fn dev_corrupt_file_random_seed_is_reproducible() {
    let (_dir, files) = store_with(&["--max-files", "1"]);
    let path = files[0].clone();
    let original = fs::read(&path).expect("data file is readable");

    let corrupt_and_read = || {
        fs::write(&path, &original).expect("data file is restorable");
        let output = caf_with_path(
            &["dev", "corrupt-file"],
            &path,
            &[
                "--preset", "random", "--seed", "42", "--start", "100", "--length", "64",
            ],
        );
        assert_eq!(code(&output), 0, "{}", stderr(&output));
        assert!(stdout(&output).contains("Using random seed: 42"));
        fs::read(&path).expect("data file is readable")
    };

    let first = corrupt_and_read();
    let second = corrupt_and_read();
    assert_eq!(first, second);
    assert_ne!(first, original);
    // Only the requested range changed.
    assert_eq!(first[..100], original[..100]);
    assert_eq!(first[164..], original[164..]);
}

#[test]
fn dev_corrupt_file_truncates_range_with_a_warning() {
    let (_dir, files) = store_with(&["--max-files", "1", "--file-size", "1024"]);
    let output = caf_with_path(
        &["dev", "corrupt-file"],
        &files[0],
        &["--start", "1000", "--length", "500"],
    );
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    let echoed = stdout(&output);
    assert!(
        echoed.contains(
            "Warning: Corruption range extends beyond file size. Truncating to 24 bytes."
        ),
        "{echoed}"
    );
    assert!(
        echoed.contains("Filled 24 bytes with random data"),
        "{echoed}"
    );
    assert_eq!(
        fs::metadata(&files[0]).expect("data file exists").len(),
        1024,
        "corruption must never change the file size"
    );
}

#[test]
fn dev_corrupt_file_invalid_preset_is_usage_error() {
    let (_dir, files) = store_with(&["--max-files", "1"]);
    let output = caf_with_path(&["dev", "corrupt-file"], &files[0], &["--preset", "nope"]);
    assert_eq!(code(&output), 2);
}

// --- help examples ----------------------------------------------------

#[test]
fn help_examples_run_successfully() {
    // Every example in the gen long help must run; sizes are the
    // documented specs with --max-files 1 to bound the work.
    for spec in [
        "4KB",
        "4048KB-10MB",
        "Type=normal,Mean=20MB,StdDev=1MB",
        "Type=gamma,Alpha=2,Beta=2MB",
        "Type=lognormal,Mean=16,StdDev=1",
    ] {
        let dir = tempdir();
        let output = generate(dir.path(), &["--max-files", "1", "--file-size", spec]);
        assert_eq!(code(&output), 0, "{spec}: {}", stderr(&output));
        assert_eq!(data_files(dir.path()).len(), 1, "{spec}");
        assert_eq!(code(&verify(dir.path(), &[])), 0, "{spec}");
    }
}

#[test]
fn subcommand_help_is_available() {
    for args in [["gen", "--help"], ["verify", "--help"], ["dev", "--help"]] {
        let output = caf(args);
        assert_eq!(code(&output), 0, "{args:?}");
    }
    let output = caf(["dev", "show", "--help"]);
    assert_eq!(code(&output), 0);
    let output = caf(["dev", "corrupt-file", "--help"]);
    assert_eq!(code(&output), 0);
}
