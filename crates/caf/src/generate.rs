//! The `caf gen` command: generate one chain of content files.
//!
//! With no stopping option, exactly 100 files are generated. `--max-files`
//! and `--max-disk-usage` are each checked before every file; the default
//! file size is 4,096 bytes; sizes below the 60-byte header are clamped
//! up by the library. `--jobs` defaults to 1 and rejects values below
//! one; it changes only how fast a large file is written, never what is
//! written. `gen` prints nothing on success.

use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context as _, Result};
use caf_store::{Generator, ParseSizeError, SizeSpec, parse_byte_size};

use crate::EXIT_FAILURE;
use crate::util::StoreRoot;

/// Files generated when neither stopping option is given.
const DEFAULT_MAX_FILES: u64 = 100;

/// Long help for `caf gen`. Every example runs successfully.
const LONG_ABOUT: &str = "\
Generate content addressable files.

This command will generate a set of linked, content addressable files.

The default behavior is to generate 100 files in the current directory.
Each file will be a fixed size of 4096 bytes:

    caf gen

You can specify the directory where the files should be generated,
the maximum number of files to generate, and indicate that each file
should be of an exact size:

    caf gen --directory /tmp/files --max-files 1000 --file-size 4KB

The --max-files is one of two stopping conditions.  A stopping
condition is what indicates when this command should stop generating
files.  The other stopping condition is \"--max-disk-usage\".  Either
stopping condition can be used.  If both stopping conditions are
specified, then this command will stop generating files as soon as any
stopping condition is met.

For example, this command will generate files until either 10000 files
are generated, or we've used 100MB of space:

    caf gen --directory /tmp/files --max-files 10000 --max-disk-usage 100MB

The --max-disk-usage is useful when we don't have a fixed file size.
This command gives you several options for specifying a range of file
sizes that can be randomly chosen.  For example, we could generate
files that have a random size between 4048KB and 10MB:

    caf gen --file-size 4048KB-10MB

Instead of specifying a range of file sizes, you can also specify a
random distribution that the file sizes should follow.  For example,
if you want to generate files that follow a normal (Gaussian)
distribution, you can specify the mean and the standard deviation by
using:

    caf gen --file-size Type=normal,Mean=20MB,StdDev=1MB

You can also use a gamma distribution.  Alpha is the shape parameter
and Beta is the scale parameter, so the mean file size is Alpha * Beta
(4MB in this example):

    caf gen --file-size Type=gamma,Alpha=2,Beta=2MB

And finally a lognormal distribution.  Note that Mean and StdDev are
the parameters of the underlying normal distribution (log space), not
byte sizes.  This example produces a median file size of e^16, which
is roughly 8.9MB:

    caf gen --file-size Type=lognormal,Mean=16,StdDev=1

Writing one very large file is normally limited by the single core
generating its content.  The --jobs option spreads that work over
worker threads:

    caf gen --max-files 1 --file-size 64MB --jobs 8

The files produced are byte for byte identical at any --jobs value, so
this only changes how long generation takes.  Small files are always
generated on one thread: splitting pays off only once a file has at
least two 1MB blocks per worker.";

/// Arguments of `caf gen`. There are no short options.
#[derive(Debug, clap::Args)]
#[command(long_about = LONG_ABOUT)]
pub struct Args {
    /// The directory where files will be generated.
    #[arg(long, value_name = "DIRECTORY")]
    directory: Option<PathBuf>,

    /// The maximum number of files to generate.
    #[arg(
        long,
        value_name = "INTEGER",
        allow_hyphen_values = true,
        value_parser = parse_max_files
    )]
    max_files: Option<i64>,

    /// The maximum disk space to use when generating files.
    #[arg(long, value_name = "SIZE", value_parser = parse_disk_usage)]
    max_disk_usage: Option<u64>,

    /// The size of the files that are generated.  Value is either in
    /// bytes or can be suffixed with kb, mb, gb, etc.  Suffix is case
    /// insensitive (we know what you mean).
    #[arg(
        long,
        value_name = "FILESIZE",
        default_value = "4096",
        value_parser = parse_file_size
    )]
    file_size: SizeSpec,

    /// Number of worker threads used to generate each file's content.
    /// Defaults to 1 (serial generation); the files produced are
    /// identical at any count. Only large files are split across
    /// workers.
    #[arg(
        long,
        value_name = "INTEGER",
        default_value_t = NonZeroUsize::MIN,
        value_parser = parse_positive
    )]
    jobs: NonZeroUsize,
}

/// Parses a worker count, rejecting values below one as usage errors.
fn parse_positive(value: &str) -> Result<NonZeroUsize> {
    value
        .parse::<NonZeroUsize>()
        .with_context(|| format!("{value:?} is not an integer of at least 1"))
}

/// Parses `--max-files`; negative values behave like zero.
fn parse_max_files(value: &str) -> Result<i64> {
    value
        .parse::<i64>()
        .with_context(|| format!("{value:?} is not an integer"))
}

/// Parses `--max-disk-usage` with the supported suffix grammar.
fn parse_disk_usage(value: &str) -> Result<u64, ParseSizeError> {
    parse_byte_size(value)
}

/// Parses `--file-size` with the fixed, range, and distribution
/// grammar; parse failures are usage errors (exit 2).
fn parse_file_size(value: &str) -> Result<SizeSpec, ParseSizeError> {
    value.parse()
}

/// Runs `caf gen`.
pub fn run(args: &Args) -> ExitCode {
    match generate(args) {
        // Successful generation produces no output.
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(EXIT_FAILURE)
        }
    }
}

/// Generates the chain `args` describes.
fn generate(args: &Args) -> Result<()> {
    let directory = StoreRoot::from(args.directory.as_deref()).resolve()?;
    let mut builder = Generator::builder(directory);

    // Only when neither option is given does
    // the 100-file default apply; a lone --max-disk-usage leaves the
    // file count unbounded and vice versa.
    match (args.max_files, args.max_disk_usage) {
        (None, None) => builder = builder.max_files(DEFAULT_MAX_FILES),
        (max_files, max_disk_usage) => {
            if let Some(count) = max_files {
                builder = builder.max_files(count.try_into().unwrap_or(0));
            }
            if let Some(bytes) = max_disk_usage {
                builder = builder.max_disk_usage(bytes);
            }
        }
    }

    // The spec was validated when it parsed; seeding the sampler can
    // still fail if the operating-system random source does, which is a
    // run failure (exit 1), not a bad value.
    let sizes = args
        .file_size
        .chooser()
        .context("seeding the file size sampler")?;

    builder
        .file_sizes(sizes)
        .jobs(args.jobs)
        .build()
        .generate()?;
    Ok(())
}
