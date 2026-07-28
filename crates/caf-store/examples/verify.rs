//! Verifies a store from the command line, for benchmarks and manual
//! differential runs against the Python implementation:
//!
//! ```text
//! cargo run --release -p caf-store --example verify -- <dir> [chunk-size] [jobs]
//! ```
//!
//! The exit status is 0 for a clean store and 1 for failed verification.
//! This example drives the library directly and prints one line per
//! diagnostic.

use std::path::PathBuf;
use std::process::ExitCode;

use caf_store::Verifier;

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let Some(dir) = args.next() else {
        eprintln!("usage: verify <dir> [chunk-size] [jobs]");
        return ExitCode::from(2);
    };
    let dir = PathBuf::from(dir);
    let mut run = || -> anyhow::Result<_> {
        let mut verifier = Verifier::new(&dir);
        if let Some(chunk_size) = args.next() {
            verifier = verifier.analysis_chunk_size(chunk_size.to_string_lossy().parse()?);
        }
        if let Some(jobs) = args.next() {
            verifier = verifier.jobs(jobs.to_string_lossy().parse()?);
        }
        Ok(verifier.verify()?)
    };
    match run() {
        Ok(report) => {
            for diagnostic in report.diagnostics() {
                println!("{}: {}", diagnostic.severity(), diagnostic.path().display());
            }
            println!(
                "files-checked={} success={}",
                report.files_checked(),
                report.success(),
            );
            if report.success() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(err) => {
            eprintln!("verify: {err:#}");
            ExitCode::FAILURE
        }
    }
}
