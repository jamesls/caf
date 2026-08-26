//! The `caf dev show` command: header diagnostics for one content file.
//!
//! A missing or non-file path is a usage error (exit 2). A file shorter
//! than 60 bytes is an error (exit 1); otherwise every header field is printed
//! even when invalid, and without `--verify-checksum` the exit status is
//! always 0. With `--verify-checksum`, the exit status is 1 when the
//! path is not CAF layout, the version-specific file identity mismatches, or
//! basic header validation fails. This is deliberately stricter than `caf verify`.
//!
//! Header bytes are interpreted by [`caf_format::RawHeader`], the shared
//! diagnostic view of the header implementation. The CLI never parses
//! header bytes itself.

use std::fs::File;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context as _, Result, bail};
use caf_format::{
    BLOCK_SIZE, Digest, Format, HEADER_SIZE, Hasher, MerkleHash, RawHeader, hash_to_path,
    parse_hash_from_path, v3_file_id_from_leaves, v3_leaf_hash,
};

use crate::EXIT_FAILURE;
use crate::style::Style;
use crate::util::{commas, hex};

/// Arguments of `caf dev show`.
#[derive(Debug, clap::Args)]
pub struct Args {
    /// Path to the CAF content file to inspect.
    #[arg(value_name = "FILEPATH", value_parser = existing_file)]
    filepath: PathBuf,

    // The help lives in the attribute rather than a doc comment so it
    // renders verbatim without linting.
    #[arg(
        long,
        help = "Calculate the version-specific file ID and verify it matches \
                the ID implied by the CAF path layout"
    )]
    verify_checksum: bool,
}

/// Validates the path argument at parse time, so a missing file or a
/// directory is a usage error (exit 2).
fn existing_file(value: &str) -> Result<PathBuf> {
    let path = PathBuf::from(value);
    let metadata = path
        .metadata()
        .with_context(|| format!("path {value:?} does not exist"))?;
    if metadata.is_dir() {
        bail!("{value:?} is a directory");
    }
    Ok(path)
}

/// Runs `caf dev show`.
pub fn run(args: &Args) -> ExitCode {
    match show(args) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("Error: {err:#}");
            ExitCode::from(EXIT_FAILURE)
        }
    }
}

/// Prints the diagnostics for one file and returns its exit status.
fn show(args: &Args) -> Result<ExitCode> {
    let style = Style::for_stdout();
    let path = &args.filepath;
    let expected_hash = PathDigest::of(path);

    let raw = read_raw_header(path)?;
    let actual_size = path
        .metadata()
        .with_context(|| format!("reading {}", path.display()))?
        .len();

    let checks = Checks::new(&raw, actual_size);
    print_header_diagnostics(path, &raw, &checks, expected_hash, actual_size, style);

    if !args.verify_checksum {
        // Diagnostic mode exits 0 even for invalid headers.
        return Ok(ExitCode::SUCCESS);
    }

    let Some(format) = checks.format else {
        print_unknown_identity_diagnostics(expected_hash, style);
        return Ok(ExitCode::from(EXIT_FAILURE));
    };
    let actual_hash =
        file_id_of_file(path, format).with_context(|| format!("reading {}", path.display()))?;
    let matches = Answer::of(expected_hash == PathDigest::InLayout(actual_hash));
    print_checksum_diagnostics(expected_hash, actual_hash, format, matches, style);

    if expected_hash.digest().is_none() || matches == Answer::No || !checks.basic_valid() {
        Ok(ExitCode::from(EXIT_FAILURE))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

/// The digest a content file's path implies.
///
/// Output reports only whether the path is in the CAF layout, not why it
/// is invalid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PathDigest {
    /// The path is a CAF layout path naming this digest.
    InLayout(Digest),
    /// The path is outside the CAF layout.
    Outside,
}

impl PathDigest {
    /// Reads the digest `path` claims by its position in the store.
    fn of(path: &Path) -> Self {
        match parse_hash_from_path(path) {
            Ok(digest) => Self::InLayout(digest),
            Err(_) => Self::Outside,
        }
    }

    /// Returns the digest, if the path is in the CAF layout.
    fn digest(self) -> Option<Digest> {
        match self {
            Self::InLayout(digest) => Some(digest),
            Self::Outside => None,
        }
    }
}

/// One `yes`/`no` answer in the diagnostics output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Answer {
    Yes,
    No,
}

impl Answer {
    /// The answer a check's outcome gives.
    fn of(holds: bool) -> Self {
        if holds { Self::Yes } else { Self::No }
    }

    /// Renders the colored marker.
    fn render(self, style: Style) -> String {
        match self {
            Self::Yes => style.green("yes"),
            Self::No => style.red("no"),
        }
    }
}

/// The basic validation checks in the `dev show` output.
struct Checks {
    format: Option<Format>,
    header_valid: Answer,
    checksum_valid: Answer,
    reserved_zero: Answer,
    length_matches: Answer,
    length_minimum: Answer,
}

impl Checks {
    fn new(raw: &RawHeader, actual_size: u64) -> Self {
        let validated = raw.validate().ok();
        Self {
            format: raw.format().ok(),
            header_valid: Answer::of(validated.is_some()),
            checksum_valid: Answer::of(raw.checksum_matches()),
            reserved_zero: Answer::of(raw.reserved_is_zero()),
            length_matches: Answer::of(raw.file_length() == actual_size),
            length_minimum: Answer::of(raw.file_length() >= HEADER_SIZE as u64),
        }
    }

    fn basic_valid(&self) -> bool {
        self.header_valid == Answer::Yes
            && self.length_matches == Answer::Yes
            && self.length_minimum == Answer::Yes
    }
}

/// Reads the first 60 bytes; short files produce an error (exit 1).
fn read_raw_header(path: &Path) -> Result<RawHeader> {
    let mut file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut buffer = [0_u8; HEADER_SIZE];
    let mut filled = 0;
    while filled < buffer.len() {
        match file.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => {
                return Err(err).with_context(|| format!("reading {}", path.display()));
            }
        }
    }
    if filled < HEADER_SIZE {
        bail!(
            "File is too small to be a CAF file: expected at least {HEADER_SIZE} bytes, \
             got {filled}."
        );
    }
    Ok(RawHeader::from_bytes(buffer)?)
}

/// Prints the header-diagnostics block.
fn print_header_diagnostics(
    path: &Path,
    raw: &RawHeader,
    checks: &Checks,
    expected_hash: PathDigest,
    actual_size: u64,
    style: Style,
) {
    let yes_no = |answer: Answer| answer.render(style);

    println!("{} {}", style.bold("File:"), path.display());
    println!(
        "{} {} bytes",
        style.bold("Actual size:"),
        commas(actual_size)
    );
    if let PathDigest::InLayout(digest) = expected_hash {
        println!("{} {digest}", style.bold("CAF hash (from path):"));
    }
    println!();
    println!("{} ({HEADER_SIZE} bytes):", style.bold("CAF header"));
    println!("  Parent Hash (0:20): {}", raw.parent());
    println!("    Root: {}", yes_no(Answer::of(raw.is_root())));
    println!("  Content Seed (20:36): {}", raw.content_seed().to_hex());
    println!("  File Length (36:44): {} bytes", commas(raw.file_length()));
    println!("    Matches actual: {}", yes_no(checks.length_matches));
    println!("  Header Checksum (44:52): {}", hex(&raw.stored_checksum()));
    println!("    Expected: {}", hex(&raw.computed_checksum()));
    println!("    Valid: {}", yes_no(checks.checksum_valid));
    if checks.format == Some(Format::V3) {
        let descriptor = raw.reserved();
        println!("  Format Descriptor (52:60): {}", hex(&descriptor));
        println!("    Marker (52:56): {}", hex(&descriptor[..4]));
        println!("    File-ID scheme (56): {}", descriptor[4]);
        println!("    Content scheme (57): {}", descriptor[5]);
        println!("    Block size log2 (58): {}", descriptor[6]);
        println!("    Flags (59): {}", descriptor[7]);
    } else {
        println!("  Reserved (52:60): {}", hex(&raw.reserved()));
        println!("    All zeros: {}", yes_no(checks.reserved_zero));
    }
    println!();
    println!("{}", style.bold("Basic validation:"));
    println!("  Header checksum valid: {}", yes_no(checks.checksum_valid));
    println!("  Header format valid: {}", yes_no(checks.header_valid));
    if checks.format != Some(Format::V3) {
        println!("  Reserved bytes zero: {}", yes_no(checks.reserved_zero));
    }
    println!(
        "  File length matches actual: {}",
        yes_no(checks.length_matches)
    );
    println!(
        "  File length >= header size: {}",
        yes_no(checks.length_minimum)
    );

    if expected_hash.digest().is_some() && !raw.is_root() {
        if let Some(store_root) = store_root_of(path) {
            println!();
            println!(
                "{} {}",
                style.bold("Parent path:"),
                hash_to_path(store_root, raw.parent()).display()
            );
        }
    }
}

/// Prints the `--verify-checksum` block.
fn print_checksum_diagnostics(
    expected_hash: PathDigest,
    actual_hash: Digest,
    format: Format,
    matches: Answer,
    style: Style,
) {
    println!();
    let (title, algorithm) = match format {
        Format::V2 => ("File checksum", "BLAKE2b-160"),
        Format::V3 => ("File ID", "CAF-Merkle-BLAKE3-160"),
    };
    println!("{} ({algorithm}):", style.bold(title));
    match expected_hash {
        PathDigest::InLayout(digest) => println!("  Expected (from path): {digest}"),
        PathDigest::Outside => {
            println!("  Expected (from path): <unavailable: not in CAF layout>");
        }
    }
    println!("  Actual: {actual_hash}");
    println!("  Matches: {}", matches.render(style));
}

/// Prints the identity result when the descriptor selects no algorithm.
fn print_unknown_identity_diagnostics(expected_hash: PathDigest, style: Style) {
    println!();
    println!("{}:", style.bold("File identity"));
    match expected_hash {
        PathDigest::InLayout(digest) => println!("  Expected (from path): {digest}"),
        PathDigest::Outside => {
            println!("  Expected (from path): <unavailable: not in CAF layout>");
        }
    }
    println!("  Actual: <unavailable: unknown header format>");
    println!("  Matches: {}", Answer::No.render(style));
}

/// The store root implied by a sharded content path: four levels up
/// from the file, resolved on the absolute path.
fn store_root_of(path: &Path) -> Option<PathBuf> {
    let absolute = std::path::absolute(path).ok()?;
    absolute.ancestors().nth(4).map(Path::to_path_buf)
}

/// Streams the whole file through BLAKE2b-160.
fn blake2b_160_of_file(path: &Path) -> std::io::Result<Digest> {
    let mut file = File::open(path)?;
    let mut hasher = Hasher::new();
    let mut buffer = vec![0_u8; BLOCK_SIZE];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buffer[..n]),
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
    Ok(hasher.finalize())
}

fn file_id_of_file(path: &Path, format: Format) -> std::io::Result<Digest> {
    match format {
        Format::V2 => blake2b_160_of_file(path),
        Format::V3 => v3_id_of_file(path),
    }
}

/// Computes the v3 ID while preserving the normative physical blocks.
fn v3_id_of_file(path: &Path) -> std::io::Result<Digest> {
    let mut file = File::open(path)?;
    let mut buffer = vec![0_u8; BLOCK_SIZE];
    let mut leaves: Vec<MerkleHash> = Vec::new();
    let mut file_length = 0_u64;
    let mut index = 0_u64;
    loop {
        let mut filled = 0;
        while filled < buffer.len() {
            match file.read(&mut buffer[filled..]) {
                Ok(0) => break,
                Ok(count) => filled += count,
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
                Err(err) => return Err(err),
            }
        }
        if filled == 0 {
            break;
        }
        leaves.push(v3_leaf_hash(index, &buffer[..filled]));
        file_length += filled as u64;
        index += 1;
        if filled < buffer.len() {
            break;
        }
    }
    Ok(Digest::from_bytes(
        v3_file_id_from_leaves(file_length, leaves).into_inner(),
    ))
}
