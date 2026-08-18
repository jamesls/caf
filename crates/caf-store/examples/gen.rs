//! Generates a store from the command line, for benchmarks and manual
//! differential runs against the Python implementation:
//!
//! ```text
//! cargo run --release -p caf-store --example gen -- <dir> <max-files> <size-spec>
//! ```
//!
//! This example drives the library directly.

use std::path::PathBuf;
use std::process::ExitCode;

use caf_store::{Generator, SizeSpec};

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let (Some(dir), Some(max_files), Some(size)) = (args.next(), args.next(), args.next()) else {
        eprintln!("usage: gen <dir> <max-files> <size-spec>");
        return ExitCode::from(2);
    };
    let dir = PathBuf::from(dir);
    let run = || -> anyhow::Result<_> {
        let spec: SizeSpec = size.to_string_lossy().parse()?;
        let report = Generator::builder(&dir)
            .max_files(max_files.to_string_lossy().parse()?)
            .file_sizes(spec.chooser()?)
            .build()
            .generate()?;
        Ok(report)
    };
    match run() {
        Ok(report) => {
            println!(
                "files={} bytes={} chain-tip={}",
                report.files_created(),
                report.bytes_written(),
                report.chain_tip(),
            );
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("gen: {err:#}");
            ExitCode::FAILURE
        }
    }
}
