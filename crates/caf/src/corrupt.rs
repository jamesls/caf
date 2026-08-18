//! The `caf dev corrupt-file` command: deliberately corrupt a byte
//! range for testing verification.
//!
//! The file, preset, and requested range are echoed first. A start offset
//! at or past the end of the file is a usage error (exit 2); a range that
//! extends past the end is truncated with a warning; the `random`
//! preset is reproducible for a given `--seed` (within this
//! implementation), but random streams are not compatible across
//! implementations.

use std::fs::OpenOptions;
use std::io::{Seek as _, SeekFrom, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context as _, Result};
use clap::ValueEnum;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng as _};

use crate::{EXIT_FAILURE, EXIT_USAGE};

/// Size of the buffer used to write corruption bytes.
const WRITE_CHUNK: usize = 64 * 1024;

/// Long help for `caf dev corrupt-file`.
const LONG_ABOUT: &str = "\
Intentionally corrupt a file for testing verification.

This command is used to test that caf correctly detects corruption.
It will modify the specified byte range in the file according to the
chosen preset.

Examples:

# Zero out bytes 100-199 in a file
caf dev corrupt-file myfile.dat --preset zero --start 100 --length 100

# Fill bytes 0-49 with random data
caf dev corrupt-file myfile.dat --preset random --start 0 --length 50

# Use a seed for reproducible corruption
caf dev corrupt-file myfile.dat --preset random --seed 42";

/// Arguments of `caf dev corrupt-file`.
#[derive(Debug, clap::Args)]
#[command(long_about = LONG_ABOUT)]
pub struct Args {
    /// Path to the file to corrupt.
    #[arg(value_name = "FILEPATH", value_parser = existing_path)]
    filepath: PathBuf,

    /// Corruption preset: "zero" fills with zeros, "random" fills with
    /// random bytes.
    #[arg(long, value_enum, default_value_t = Preset::Random)]
    preset: Preset,

    /// Starting byte offset for corruption.
    #[arg(long, value_name = "INTEGER", default_value_t = 0)]
    start: u64,

    /// Number of bytes to corrupt.
    #[arg(long, value_name = "INTEGER", default_value_t = 100)]
    length: u64,

    /// Random seed for reproducible corruption (only applies to
    /// "random" preset).
    #[arg(long, value_name = "INTEGER")]
    seed: Option<u64>,
}

/// The supported corruption presets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Preset {
    /// Overwrite the range with zero bytes.
    Zero,
    /// Overwrite the range with random bytes.
    Random,
}

/// Validates the path argument at parse time, so a missing file is a
/// usage error (exit 2).
fn existing_path(value: &str) -> Result<PathBuf> {
    let path = PathBuf::from(value);
    path.metadata()
        .with_context(|| format!("path {value:?} does not exist"))?;
    Ok(path)
}

/// Runs `caf dev corrupt-file`.
pub fn run(args: &Args) -> ExitCode {
    match corrupt(args) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("Error: {err:#}");
            ExitCode::from(EXIT_FAILURE)
        }
    }
}

/// Corrupts the requested range and returns the exit status.
fn corrupt(args: &Args) -> Result<ExitCode> {
    let path = &args.filepath;
    println!("Corrupting file: {}", path.display());
    println!(
        "Preset: {}",
        match args.preset {
            Preset::Zero => "zero",
            Preset::Random => "random",
        }
    );
    // The requested range is echoed before validation;
    // for a zero-length range the end offset is start - 1.
    let end = i128::from(args.start) + i128::from(args.length) - 1;
    println!(
        "Range: bytes {} to {end} ({} bytes)",
        args.start, args.length
    );

    let file_size = path
        .metadata()
        .with_context(|| format!("reading {}", path.display()))?
        .len();
    if args.start >= file_size {
        eprintln!(
            "Error: Start offset {} is beyond file size {file_size}",
            args.start
        );
        return Ok(ExitCode::from(EXIT_USAGE));
    }
    let mut length = args.length;
    if length > file_size - args.start {
        let truncated = file_size - args.start;
        println!(
            "Warning: Corruption range extends beyond file size. \
             Truncating to {truncated} bytes."
        );
        length = truncated;
    }

    apply(args, length).with_context(|| format!("corrupting {}", path.display()))?;
    println!("Corruption complete.");
    Ok(ExitCode::SUCCESS)
}

/// Overwrites `length` bytes at the validated offset with the preset's
/// fill, streaming in bounded chunks.
fn apply(args: &Args, length: u64) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&args.filepath)?;
    file.seek(SeekFrom::Start(args.start))?;

    match args.preset {
        Preset::Zero => {
            write_fill(&mut file, length, |chunk| chunk.fill(0))?;
            println!("Zeroed out {length} bytes");
        }
        Preset::Random => {
            // A seed selects a reproducible generator; without one the
            // OS-seeded thread generator is used.
            let mut seeded;
            let mut unseeded;
            let rng: &mut dyn RngCore = if let Some(seed) = args.seed {
                println!("Using random seed: {seed}");
                seeded = StdRng::seed_from_u64(seed);
                &mut seeded
            } else {
                unseeded = rand::rng();
                &mut unseeded
            };
            write_fill(&mut file, length, |chunk| rng.fill_bytes(chunk))?;
            println!("Filled {length} bytes with random data");
        }
    }
    Ok(())
}

/// Writes `length` bytes produced by `populate` to `file` in chunks.
fn write_fill(
    mut file: impl Write,
    length: u64,
    mut populate: impl FnMut(&mut [u8]),
) -> std::io::Result<()> {
    let mut buffer = vec![0_u8; WRITE_CHUNK.min(usize::try_from(length).unwrap_or(WRITE_CHUNK))];
    let mut remaining = length;
    while remaining > 0 {
        let take = usize::try_from(remaining.min(buffer.len() as u64))
            .expect("chunk length is bounded by the buffer size");
        let chunk = &mut buffer[..take];
        populate(chunk);
        file.write_all(chunk)?;
        remaining -= take as u64;
    }
    Ok(())
}
