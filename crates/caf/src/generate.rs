//! The `caf gen` command: generate one chain of content files.
//!
//! With no stopping option, exactly 100 files are generated. `--max-files`
//! and `--max-disk-usage` are each checked before every file; the default
//! file size is 4,096 bytes; fixed and range sizes below the 60-byte
//! header are clamped up by the library, and distributions are sampled
//! inside an explicit band. `--jobs` defaults to a CPU-aware worker budget and
//! rejects values below one; it changes only how fast a large file is
//! written, never what is written. `gen` shows live progress when
//! standard error is a terminal and prints nothing when output is
//! redirected.

use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use caf_format::Format;
use caf_store::{
    GenerationSeed, Generator, ParseSizeError, SizeSpec, default_jobs, parse_byte_size,
};

use crate::EXIT_FAILURE;
use crate::progress::{Basis, ProgressBar};
use crate::util::StoreRoot;

/// Files generated when neither stopping option is given.
const DEFAULT_MAX_FILES: u64 = 100;

/// Long help for `caf gen`. Every example runs successfully.
pub(super) const LONG_ABOUT: &str = "\
Generate content addressable files.

This command will generate a set of linked, content addressable files.

The default behavior is to generate 100 files in the current directory.
Each file will be a fixed size of 4096 bytes:

    caf gen

You can specify the directory where the files should be generated,
the maximum number of files to generate, and indicate that each file
should be of an exact size:

    caf gen --directory /tmp/files --max-files 1000 --file-size 4KB

Use --seed with CAF v3 to reproduce a dataset. In a fresh directory, identical generation
arguments and seed text produce identical file sizes, contents, relative paths,
and CAF metadata across releases. Directory and worker count may differ.
Seed text is used exactly as given; an empty seed or --format v2 is a usage error:

    caf gen --seed blahblah --max-files 100 --file-size 4096 --format v3

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
random distribution that the file sizes should follow.  Every
distribution is sampled inside a band from Min to Max.  Min defaults
to 60 bytes, the header size.  Max is required because both
distributions have heavy tails.  A sample outside the band is redrawn,
so no file is ever larger than Max.  Before sampling, a conservative
probability bound must show that the band holds at least 0.5% of the
distribution; unsupported bands fail before any files are written.

A lognormal distribution takes the median file size in bytes and Sigma,
the spread in log space.  Sigma=1 puts 68% of files within a factor of
2.7 of the median; a small Sigma such as 0.05 gives a tight bell curve
around the median:

    caf gen --file-size Type=lognormal,Median=1MB,Sigma=1,Max=1GB
    caf gen --file-size Type=lognormal,Median=20MB,Sigma=0.05,Max=30MB

A Pareto distribution produces many small files and a few very large
ones.  Min is the smallest file, Max the largest, and Alpha controls
how fast the count falls off; smaller Alpha means more large files.
The fraction of files larger than X is (Min / X) ^ Alpha.  This example
keeps half the files under 7KB while about one in 800 exceeds 1MB:

    caf gen --file-size Type=pareto,Min=4KB,Max=1GB,Alpha=1.2

Parameter values accept decimals with a size suffix (1.5MB) and plain
decimals for Sigma and Alpha.

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
pub struct Args {
    /// The directory where files will be generated.
    #[arg(long, value_name = "DIRECTORY")]
    directory: Option<PathBuf>,

    /// CAF file format to generate. Version 3 is the default.
    #[arg(long, value_enum, default_value = "v3")]
    format: FormatArg,

    /// Reproduce a CAF v3 dataset from exact, nonempty UTF-8 seed text.
    #[arg(long, value_name = "TEXT")]
    seed: Option<GenerationSeed>,

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
    /// insensitive (we know what you mean).  A random distribution
    /// (Type=lognormal or Type=pareto) is sampled between Min and Max;
    /// see --help for the full grammar.
    #[arg(
        long,
        value_name = "FILESIZE",
        default_value = "4096",
        value_parser = parse_file_size
    )]
    file_size: SizeSpec,

    /// Number of worker threads used to generate each file's content.
    /// Defaults to a CPU-aware worker budget; the files produced are
    /// identical at any count. Only large files are split across workers.
    #[arg(
        long,
        value_name = "INTEGER",
        default_value_t = default_jobs(),
        value_parser = parse_positive
    )]
    jobs: NonZeroUsize,
}

/// Values accepted by `--format`.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum FormatArg {
    V2,
    V3,
}

impl From<FormatArg> for Format {
    fn from(format: FormatArg) -> Self {
        match format {
            FormatArg::V2 => Self::V2,
            FormatArg::V3 => Self::V3,
        }
    }
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
    if args.seed.is_some() && matches!(args.format, FormatArg::V2) {
        clap::Error::raw(
            clap::error::ErrorKind::ArgumentConflict,
            "--seed requires --format v3",
        )
        .exit();
    }
    let progress = ProgressBar::new("Generate", Basis::AnyLimit);
    match generate(args, &progress) {
        Ok(()) => {
            progress.finish(true);
            ExitCode::SUCCESS
        }
        Err(err) => {
            progress.clear();
            eprintln!("error: {err:#}");
            ExitCode::from(EXIT_FAILURE)
        }
    }
}

/// Generates the chain `args` describes.
fn generate(args: &Args, progress: &Arc<ProgressBar>) -> Result<()> {
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
    let sizes = if let Some(seed) = &args.seed {
        builder = builder.seed(seed.clone());
        args.file_size.chooser_seeded(seed)
    } else {
        args.file_size
            .chooser()
            .context("seeding the file size sampler")?
    };

    builder = builder
        .format(args.format.into())
        .file_sizes(sizes)
        .jobs(args.jobs);
    if progress.enabled() {
        let progress = Arc::clone(progress);
        builder = builder.progress(move |snapshot| progress.update(snapshot));
    }
    builder.build().generate()?;
    Ok(())
}
