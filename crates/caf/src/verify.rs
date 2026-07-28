//! The `caf verify` command: verify a store and analyze corruption.
//!
//! The header lines and the Error Analysis report go to standard output.
//! Diagnostic lines go to standard error, and the exit status is 0 for a clean
//! store and 1 for any failure. `--chunk-size` rejects values below one
//! and `--jobs` defaults to 1 and rejects values below one.

use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context as _, Result};
use caf_store::{DEFAULT_ANALYSIS_CHUNK_SIZE, Verifier};

use crate::style::Style;
use crate::util::{StoreRoot, commas};
use crate::{EXIT_FAILURE, render};

/// Long help for `caf verify`.
const LONG_ABOUT: &str = "\
Verify content addressable files and analyze corruption.

This command verifies all CAF files in the specified directory and
provides detailed corruption analysis if any files are corrupted.

The --chunk-size option controls the granularity of corruption
detection:

    - 512 bytes: Fine-grained analysis, slower but more precise
    - 4096 bytes: Standard 4KB block analysis (default)
    - 65536 bytes: Fast scanning for large files

When corruption is detected, the verifier will:

    - Identify exact corrupted byte ranges
    - Analyze corruption patterns (zero-filled, sparse, random, etc.)
    - Provide visual corruption maps";

/// Arguments of `caf verify`.
#[derive(Debug, clap::Args)]
#[command(long_about = LONG_ABOUT)]
pub struct Args {
    /// The directory to verify. Defaults to current directory.
    #[arg(long, value_name = "DIRECTORY")]
    directory: Option<PathBuf>,

    /// Chunk size in bytes for corruption analysis. Smaller values
    /// provide more granular corruption detection but take longer.
    /// Common values: 512 (fine-grained), 4096 (4KB blocks), 65536
    /// (64KB chunks).
    #[arg(
        long,
        value_name = "INTEGER",
        default_value_t = DEFAULT_ANALYSIS_CHUNK_SIZE,
        value_parser = parse_positive
    )]
    chunk_size: NonZeroUsize,

    /// Number of worker threads for file validation. Defaults to 1
    /// (serial verification); results are identical at any count.
    #[arg(
        long,
        value_name = "INTEGER",
        default_value_t = NonZeroUsize::MIN,
        value_parser = parse_positive
    )]
    jobs: NonZeroUsize,
}

/// Parses a worker or chunk count, rejecting values below one as usage
/// errors.
fn parse_positive(value: &str) -> Result<NonZeroUsize> {
    value
        .parse::<NonZeroUsize>()
        .with_context(|| format!("{value:?} is not an integer of at least 1"))
}

/// Runs `caf verify`.
pub fn run(args: &Args) -> ExitCode {
    let out = Style::for_stdout();
    let err = Style::for_stderr();

    let failed = match verify(args, out, err) {
        Ok(failed) => failed,
        Err(error) => {
            // A store-level failure (not a store, unreadable file,
            // pathological nesting) fails verification; the not-a-store
            // message is the error's Display.
            eprintln!("{} {error:#}", err.red_bold("ERROR:"));
            true
        }
    };

    if failed {
        println!("{} Verification failed.", out.red("✗"));
        ExitCode::from(EXIT_FAILURE)
    } else {
        println!("{} All files successfully verified.", out.green("✓"));
        ExitCode::SUCCESS
    }
}

/// Verifies the store `args` names, rendering the report, and returns
/// whether verification failed.
fn verify(args: &Args, out: Style, err: Style) -> Result<bool> {
    let directory = StoreRoot::from(args.directory.as_deref()).resolve()?;

    println!(
        "Verifying file contents in: {}",
        out.bold(directory.display())
    );
    println!(
        "{}",
        out.dim(format!(
            "Analysis chunk size: {} bytes",
            commas(args.chunk_size.get() as u64)
        ))
    );

    let report = Verifier::new(&directory)
        .analysis_chunk_size(args.chunk_size)
        .jobs(args.jobs)
        .verify()?;
    render::diagnostics(report.diagnostics(), err);
    render::error_analysis(&report, out);
    Ok(!report.success())
}
