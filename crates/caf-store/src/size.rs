//! File-size grammar and selection for generation.
//!
//! The `--file-size` and `--max-disk-usage` grammar accepts plain byte
//! counts, two-character `kb`/`mb`/`gb`/`tb` suffixes (case-insensitive),
//! inclusive `START-END` ranges, and the `Type=…` distribution shorthand.
//! [`SizeSpec`] is the parsed grammar; [`SizeChooser`] draws one size per
//! file from it.
//!
//! Random streams are not compatible across implementations. The grammar,
//! parameter meaning, bounds, and statistical behavior are stable;
//! lognormal parameters stay in log space. Unknown or
//! missing distribution parameters are rejected at parse time rather than
//! causing generation to fail later.

use std::backtrace::Backtrace;
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};
use std::io;
use std::ops::{Bound, RangeBounds};
use std::str::FromStr;

use rand::rngs::StdRng;
use rand::{Rng as _, SeedableRng};
use rand_distr::{Distribution as _, Gamma, LogNormal, Normal};

use crate::random;

/// Multipliers for the two-character size suffixes. The grammar
/// matches them case-insensitively against the last two characters of a
/// token; single-letter suffixes (`1k`, `100b`) are errors.
const SUFFIXES: [(&str, u64); 4] = [
    ("kb", 1 << 10),
    ("mb", 1 << 20),
    ("gb", 1 << 30),
    ("tb", 1 << 40),
];

/// Parses a byte count with an optional `kb`/`mb`/`gb`/`tb` suffix.
///
/// This is the grammar `--max-disk-usage`, range endpoints, and
/// distribution parameter values share: `4096`, `2kb`, `1MB`, `1tb`.
/// Suffixes are case-insensitive.
///
/// # Examples
///
/// ```
/// use caf_store::parse_byte_size;
///
/// assert_eq!(parse_byte_size("4096")?, 4096);
/// assert_eq!(parse_byte_size("2Kb")?, 2048);
/// assert_eq!(parse_byte_size("1tb")?, 1 << 40);
/// # Ok::<(), caf_store::ParseSizeError>(())
/// ```
///
/// # Errors
///
/// Returns a [`ParseSizeError`] if the token is not an unsigned integer
/// with an optional known suffix, or if the suffixed value overflows the
/// 64-bit byte range.
pub fn parse_byte_size(value: impl AsRef<str>) -> Result<u64, ParseSizeError> {
    let value = value.as_ref();
    match split_suffix(value) {
        Some((prefix, multiplier)) => {
            let count = parse_integer(prefix, value)?;
            count.checked_mul(multiplier).ok_or_else(|| {
                ParseSizeError::new(ParseSizeErrorKind::Overflow {
                    input: value.to_owned(),
                })
            })
        }
        None => parse_integer(value, value),
    }
}

/// Splits a trailing size suffix off `value`, if the last two characters
/// form one.
fn split_suffix(value: &str) -> Option<(&str, u64)> {
    let split = value.len().checked_sub(2)?;
    let (prefix, suffix) = value.split_at_checked(split)?;
    let suffix = suffix.to_ascii_lowercase();
    SUFFIXES
        .iter()
        .find(|(known, _)| *known == suffix)
        .map(|(_, multiplier)| (prefix, *multiplier))
}

/// Parses `token` as an unsigned byte count, reporting `input` (the full
/// original token) on failure.
fn parse_integer(token: &str, input: &str) -> Result<u64, ParseSizeError> {
    token.parse::<u64>().map_err(|source| {
        ParseSizeError::new(ParseSizeErrorKind::InvalidInteger {
            input: input.to_owned(),
            source,
        })
    })
}

/// A parsed `--file-size` specification.
///
/// Parse one from the CLI grammar with [`FromStr`], or build one
/// directly with the constructors. Every constructor validates its
/// arguments, so a `SizeSpec` always describes a samplable distribution;
/// [`SizeSpec::chooser`] then draws the sampler's random seed.
///
/// # Examples
///
/// ```
/// use caf_store::SizeSpec;
///
/// assert_eq!("4096".parse::<SizeSpec>()?, SizeSpec::fixed(4096));
/// assert_eq!("1kb-2kb".parse::<SizeSpec>()?, SizeSpec::range(1024..=2048)?);
/// assert_eq!(
///     "Type=normal,Mean=1kb,StdDev=0".parse::<SizeSpec>()?,
///     SizeSpec::normal(1024.0, 0.0)?,
/// );
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct SizeSpec {
    kind: SpecKind,
}

/// The validated forms. Distributions are stored as their samplers:
/// building one is how the parameters are checked, and the check happens
/// once, in the constructor.
#[derive(Clone, Copy, Debug, PartialEq)]
enum SpecKind {
    Fixed(u64),
    /// Invariant: `start <= end`.
    Range {
        start: u64,
        end: u64,
    },
    Normal(Normal<f64>),
    Gamma(Gamma<f64>),
    LogNormal(LogNormal<f64>),
}

impl SizeSpec {
    /// Every file gets exactly `bytes` bytes.
    #[must_use]
    pub fn fixed(bytes: u64) -> Self {
        Self {
            kind: SpecKind::Fixed(bytes),
        }
    }

    /// Each size is an independent uniform sample from `range`.
    ///
    /// The `START-END` grammar is inclusive at both ends, so it parses to
    /// `1024..=2048`. Any other range is normalized to inclusive bounds, and an
    /// unbounded side spans the whole 64-bit byte range.
    ///
    /// # Errors
    ///
    /// Returns a [`SizeSpecError`] if the range contains no sizes: its
    /// start exceeds its end, or an exclusive bound at the edge of the 64-bit
    /// range excludes everything beyond it (`..0`, or an excluded
    /// start of `u64::MAX`).
    pub fn range(range: impl RangeBounds<u64>) -> Result<Self, SizeSpecError> {
        // Exclusive bounds move inward one step; at the edge of the
        // 64-bit range there is no inward step, so the range is empty.
        let start = match range.start_bound() {
            Bound::Included(&start) => start,
            Bound::Excluded(&start) => start
                .checked_add(1)
                .ok_or_else(|| SizeSpecError::new(SizeSpecErrorKind::EmptyExclusiveStart))?,
            Bound::Unbounded => 0,
        };
        let end = match range.end_bound() {
            Bound::Included(&end) => end,
            Bound::Excluded(&end) => end
                .checked_sub(1)
                .ok_or_else(|| SizeSpecError::new(SizeSpecErrorKind::EmptyExclusiveEnd))?,
            Bound::Unbounded => u64::MAX,
        };
        if start > end {
            return Err(SizeSpecError::new(SizeSpecErrorKind::EmptyRange {
                start,
                end,
            }));
        }
        Ok(Self {
            kind: SpecKind::Range { start, end },
        })
    }

    /// Gaussian sizes in bytes with the given mean and standard deviation.
    ///
    /// # Errors
    ///
    /// Returns a [`SizeSpecError`] if the parameters are outside the
    /// sampler's domain (a negative or non-finite standard deviation).
    pub fn normal(mean: f64, std_dev: f64) -> Result<Self, SizeSpecError> {
        let dist = Normal::new(mean, std_dev).map_err(|err| invalid_distribution("normal", err))?;
        Ok(Self {
            kind: SpecKind::Normal(dist),
        })
    }

    /// Gamma-distributed sizes: shape `alpha`, scale `beta` bytes
    /// (mean = `alpha` × `beta`).
    ///
    /// # Errors
    ///
    /// Returns a [`SizeSpecError`] if the parameters are outside the
    /// sampler's domain (a non-positive shape or scale).
    pub fn gamma(alpha: f64, beta: f64) -> Result<Self, SizeSpecError> {
        let dist = Gamma::new(alpha, beta).map_err(|err| invalid_distribution("gamma", err))?;
        Ok(Self {
            kind: SpecKind::Gamma(dist),
        })
    }

    /// Lognormal sizes; `mean` and `std_dev` parameterize the underlying
    /// normal distribution (log space), not byte sizes.
    ///
    /// # Errors
    ///
    /// Returns a [`SizeSpecError`] if the parameters are outside the
    /// sampler's domain (a negative or non-finite standard deviation).
    pub fn lognormal(mean: f64, std_dev: f64) -> Result<Self, SizeSpecError> {
        let dist =
            LogNormal::new(mean, std_dev).map_err(|err| invalid_distribution("lognormal", err))?;
        Ok(Self {
            kind: SpecKind::LogNormal(dist),
        })
    }

    /// Parses the `--file-size` grammar, trying shapes in this order:
    /// plain integer, distribution shorthand (contains
    /// `,`), inclusive range (contains `-`), then suffixed fixed size.
    ///
    /// This is what [`FromStr`] parses, so `input.parse()` is equivalent.
    ///
    /// # Errors
    ///
    /// Returns a [`ParseSizeError`] if `input` matches no shape of the
    /// grammar, or names values no sampler accepts.
    pub fn parse(input: &str) -> Result<Self, ParseSizeError> {
        if let Ok(bytes) = input.parse::<u64>() {
            return Ok(Self::fixed(bytes));
        }
        if input.contains(',') {
            return parse_shorthand(input);
        }
        if input.contains('-') {
            let parts: Vec<&str> = input.split('-').collect();
            let &[start, end] = parts.as_slice() else {
                return Err(ParseSizeError::new(ParseSizeErrorKind::MalformedRange {
                    input: input.to_owned(),
                }));
            };
            return Self::range(parse_byte_size(start)?..=parse_byte_size(end)?)
                .map_err(ParseSizeError::invalid_spec);
        }
        if split_suffix(input).is_some() {
            return Ok(Self::fixed(parse_byte_size(input)?));
        }
        Err(ParseSizeError::new(ParseSizeErrorKind::UnknownSpec {
            input: input.to_owned(),
        }))
    }

    /// Returns a sampler for this spec.
    ///
    /// # Examples
    ///
    /// ```
    /// use caf_store::SizeSpec;
    ///
    /// let mut sizes = "60-60".parse::<SizeSpec>()?.chooser()?;
    /// assert_eq!(sizes.next_size()?, 60);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns the [`io::Error`] the operating-system random source
    /// reported while seeding the sampler. The spec's parameters were
    /// validated when it was built.
    pub fn chooser(&self) -> io::Result<SizeChooser> {
        let kind = match self.kind {
            SpecKind::Fixed(bytes) => ChooserKind::Fixed(bytes),
            SpecKind::Range { start, end } => ChooserKind::Range {
                start,
                end,
                rng: os_seeded_rng()?,
            },
            SpecKind::Normal(dist) => ChooserKind::Normal {
                dist,
                rng: os_seeded_rng()?,
            },
            SpecKind::Gamma(dist) => ChooserKind::Gamma {
                dist,
                rng: os_seeded_rng()?,
            },
            SpecKind::LogNormal(dist) => ChooserKind::LogNormal {
                dist,
                rng: os_seeded_rng()?,
            },
        };
        Ok(SizeChooser { kind })
    }
}

impl FromStr for SizeSpec {
    type Err = ParseSizeError;

    fn from_str(input: &str) -> Result<Self, ParseSizeError> {
        Self::parse(input)
    }
}

/// Parses the `Type=<type>,Key=Value,…` distribution shorthand.
fn parse_shorthand(input: &str) -> Result<SizeSpec, ParseSizeError> {
    let mut type_name = None;
    let mut params: Vec<(&str, &str)> = Vec::new();
    for item in input.split(',') {
        let mut fields = item.split('=');
        let (Some(key), Some(value), None) = (fields.next(), fields.next(), fields.next()) else {
            return Err(ParseSizeError::new(
                ParseSizeErrorKind::MalformedParameter {
                    item: item.to_owned(),
                },
            ));
        };
        if key == "Type" {
            type_name = Some(value);
        } else {
            params.push((key, value));
        }
    }
    let Some(type_name) = type_name else {
        return Err(ParseSizeError::new(ParseSizeErrorKind::MissingType));
    };
    let spec = match type_name {
        "normal" => {
            let (mean, std_dev) = two_params("normal", &params, "Mean", "StdDev")?;
            SizeSpec::normal(mean, std_dev)
        }
        "gamma" => {
            let (alpha, beta) = two_params("gamma", &params, "Alpha", "Beta")?;
            SizeSpec::gamma(alpha, beta)
        }
        "lognormal" => {
            let (mean, std_dev) = two_params("lognormal", &params, "Mean", "StdDev")?;
            SizeSpec::lognormal(mean, std_dev)
        }
        other => {
            return Err(ParseSizeError::new(ParseSizeErrorKind::UnknownType {
                name: other.to_owned(),
            }));
        }
    };
    spec.map_err(ParseSizeError::invalid_spec)
}

/// Extracts exactly the two named parameters. Unknown and missing names
/// are errors; duplicates keep the last value.
fn two_params(
    type_name: &'static str,
    params: &[(&str, &str)],
    first: &'static str,
    second: &'static str,
) -> Result<(f64, f64), ParseSizeError> {
    for &(name, _) in params {
        if name != first && name != second {
            return Err(ParseSizeError::new(ParseSizeErrorKind::UnknownParameter {
                type_name,
                name: name.to_owned(),
            }));
        }
    }
    let lookup = |wanted: &'static str| {
        let &(_, value) = params
            .iter()
            .rev()
            .find(|(name, _)| *name == wanted)
            .ok_or_else(|| {
                ParseSizeError::new(ParseSizeErrorKind::MissingParameter {
                    type_name,
                    name: wanted,
                })
            })?;
        // Parameter values are integers in the grammar and become
        // floating-point values inside the samplers, with precision loss
        // above 2^53.
        #[expect(
            clippy::cast_precision_loss,
            reason = "matches Python's int-to-float conversion in the samplers"
        )]
        Ok(parse_byte_size(value)? as f64)
    };
    Ok((lookup(first)?, lookup(second)?))
}

/// Builds a [`SizeSpecError`] for parameters a sampler rejects, keeping
/// the sampler's own error as the cause. `rand_distr` is pre-1.0, so the
/// error type stays erased instead of becoming part of this API.
fn invalid_distribution(
    type_name: &'static str,
    source: impl Error + Send + Sync + 'static,
) -> SizeSpecError {
    SizeSpecError::new(SizeSpecErrorKind::InvalidDistribution {
        type_name,
        source: Box::new(source),
    })
}

/// Seeds the sampling RNG from the operating-system random source.
fn os_seeded_rng() -> io::Result<StdRng> {
    let mut seed = <StdRng as SeedableRng>::Seed::default();
    random::fill(&mut seed)?;
    Ok(StdRng::from_seed(seed))
}

/// Draws one file size per call from a [`SizeSpec`] (or a custom
/// closure via [`SizeChooser::from_fn`]).
///
/// Distribution samples are truncated toward zero, then made non-negative.
/// The generator later clamps every size below 60 bytes up to the header
/// size, so choosers may return any value.
pub struct SizeChooser {
    kind: ChooserKind,
}

enum ChooserKind {
    Fixed(u64),
    Range { start: u64, end: u64, rng: StdRng },
    Normal { dist: Normal<f64>, rng: StdRng },
    Gamma { dist: Gamma<f64>, rng: StdRng },
    LogNormal { dist: LogNormal<f64>, rng: StdRng },
    Custom(Box<dyn FnMut() -> u64 + Send>),
}

impl SizeChooser {
    /// A chooser that always returns `bytes`.
    #[must_use]
    pub fn fixed(bytes: u64) -> Self {
        Self {
            kind: ChooserKind::Fixed(bytes),
        }
    }

    /// A chooser driven by a caller-supplied function.
    ///
    /// This is the extension point for size sources the CLI
    /// grammar does not cover: empirical distributions, replayed size
    /// traces, or deterministic sequences in tests.
    #[must_use]
    pub fn from_fn(choose: impl FnMut() -> u64 + Send + 'static) -> Self {
        Self {
            kind: ChooserKind::Custom(Box::new(choose)),
        }
    }

    /// Returns the size in bytes for the next file.
    ///
    /// # Errors
    ///
    /// Returns a [`SampleError`] if a distribution sample is not finite.
    pub fn next_size(&mut self) -> Result<u64, SampleError> {
        match &mut self.kind {
            ChooserKind::Fixed(bytes) => Ok(*bytes),
            ChooserKind::Range { start, end, rng } => Ok(rng.random_range(*start..=*end)),
            ChooserKind::Normal { dist, rng } => truncated_magnitude(dist.sample(rng)),
            ChooserKind::Gamma { dist, rng } => truncated_magnitude(dist.sample(rng)),
            ChooserKind::LogNormal { dist, rng } => truncated_magnitude(dist.sample(rng)),
            ChooserKind::Custom(choose) => Ok(choose()),
        }
    }
}

impl Debug for SizeChooser {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match &self.kind {
            ChooserKind::Fixed(bytes) => write!(f, "SizeChooser::Fixed({bytes})"),
            ChooserKind::Range { start, end, .. } => {
                write!(f, "SizeChooser::Range({start}..={end})")
            }
            ChooserKind::Normal { .. } => f.write_str("SizeChooser::Normal"),
            ChooserKind::Gamma { .. } => f.write_str("SizeChooser::Gamma"),
            ChooserKind::LogNormal { .. } => f.write_str("SizeChooser::LogNormal"),
            ChooserKind::Custom(_) => f.write_str("SizeChooser::Custom"),
        }
    }
}

/// Truncates `sample` toward zero, then takes its magnitude. Finite
/// values beyond the 64-bit range saturate to
/// `u64::MAX`.
fn truncated_magnitude(sample: f64) -> Result<u64, SampleError> {
    if !sample.is_finite() {
        return Err(SampleError::new());
    }
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "trunc().abs() is non-negative; the cast saturates by design"
    )]
    Ok(sample.trunc().abs() as u64)
}

/// Error parsing a size specification.
///
/// Produced by [`parse_byte_size`] and [`SizeSpec`]'s [`FromStr`] impl.
/// Every condition is a malformed or unsamplable specification, which
/// the CLI reports as a usage error (exit 2).
#[derive(Debug)]
pub struct ParseSizeError {
    inner: Box<ParseSizeErrorInner>,
}

/// Boxed so `Result<_, ParseSizeError>` stays one pointer wide on the
/// success path; the rejected specification is the payload.
#[derive(Debug)]
struct ParseSizeErrorInner {
    kind: ParseSizeErrorKind,
    #[expect(dead_code, reason = "surfaced through Debug output only")]
    backtrace: Backtrace,
}

#[derive(Debug)]
enum ParseSizeErrorKind {
    InvalidInteger {
        input: String,
        source: std::num::ParseIntError,
    },
    Overflow {
        input: String,
    },
    UnknownSpec {
        input: String,
    },
    MalformedRange {
        input: String,
    },
    MissingType,
    UnknownType {
        name: String,
    },
    MalformedParameter {
        item: String,
    },
    UnknownParameter {
        type_name: &'static str,
        name: String,
    },
    MissingParameter {
        type_name: &'static str,
        name: &'static str,
    },
    /// The grammar was well formed, but the values it named do not
    /// describe a samplable spec.
    InvalidSpec {
        source: SizeSpecError,
    },
}

impl ParseSizeError {
    fn new(kind: ParseSizeErrorKind) -> Self {
        Self {
            inner: Box::new(ParseSizeErrorInner {
                kind,
                backtrace: Backtrace::capture(),
            }),
        }
    }

    fn invalid_spec(source: SizeSpecError) -> Self {
        Self::new(ParseSizeErrorKind::InvalidSpec { source })
    }

    /// Returns `true` if a token was not a valid unsigned integer.
    #[must_use]
    pub fn is_invalid_integer(&self) -> bool {
        matches!(self.inner.kind, ParseSizeErrorKind::InvalidInteger { .. })
    }

    /// Returns `true` if a suffixed value overflowed 64 bits.
    #[must_use]
    pub fn is_overflow(&self) -> bool {
        matches!(self.inner.kind, ParseSizeErrorKind::Overflow { .. })
    }

    /// Returns `true` if the spec matched no known shape.
    #[must_use]
    pub fn is_unknown_spec(&self) -> bool {
        matches!(self.inner.kind, ParseSizeErrorKind::UnknownSpec { .. })
    }

    /// Returns `true` if a range did not have exactly two endpoints.
    #[must_use]
    pub fn is_malformed_range(&self) -> bool {
        matches!(self.inner.kind, ParseSizeErrorKind::MalformedRange { .. })
    }

    /// Returns `true` if distribution shorthand lacked `Type=`.
    #[must_use]
    pub fn is_missing_type(&self) -> bool {
        matches!(self.inner.kind, ParseSizeErrorKind::MissingType)
    }

    /// Returns `true` for an unknown distribution type.
    #[must_use]
    pub fn is_unknown_type(&self) -> bool {
        matches!(self.inner.kind, ParseSizeErrorKind::UnknownType { .. })
    }

    /// Returns `true` if a shorthand item was not `Key=Value`.
    #[must_use]
    pub fn is_malformed_parameter(&self) -> bool {
        matches!(
            self.inner.kind,
            ParseSizeErrorKind::MalformedParameter { .. }
        )
    }

    /// Returns `true` for a parameter name the distribution rejects.
    #[must_use]
    pub fn is_unknown_parameter(&self) -> bool {
        matches!(self.inner.kind, ParseSizeErrorKind::UnknownParameter { .. })
    }

    /// Returns `true` if a required distribution parameter was absent.
    #[must_use]
    pub fn is_missing_parameter(&self) -> bool {
        matches!(self.inner.kind, ParseSizeErrorKind::MissingParameter { .. })
    }

    /// Returns the [`SizeSpecError`] a well-formed specification was
    /// rejected with, if that is why parsing failed.
    #[must_use]
    pub fn invalid_spec_error(&self) -> Option<&SizeSpecError> {
        match &self.inner.kind {
            ParseSizeErrorKind::InvalidSpec { source } => Some(source),
            _ => None,
        }
    }
}

impl Display for ParseSizeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match &self.inner.kind {
            ParseSizeErrorKind::InvalidInteger { input, .. } => {
                write!(
                    f,
                    "invalid size specifier {input:?}: not an unsigned integer"
                )
            }
            ParseSizeErrorKind::Overflow { input } => {
                write!(
                    f,
                    "size specifier {input:?} overflows the 64-bit byte range"
                )
            }
            ParseSizeErrorKind::UnknownSpec { input } => {
                write!(f, "unknown size specifier {input:?}")
            }
            ParseSizeErrorKind::MalformedRange { input } => write!(
                f,
                "bad size range {input:?}: should be startsize-endsize (e.g. 1mb-5mb)"
            ),
            ParseSizeErrorKind::MissingType => {
                f.write_str("missing Type=<type> in file size specifier")
            }
            ParseSizeErrorKind::UnknownType { name } => write!(
                f,
                "unknown Type {name:?}, must be one of: normal,gamma,lognormal"
            ),
            ParseSizeErrorKind::MalformedParameter { item } => {
                write!(f, "malformed size parameter {item:?}: expected Key=Value")
            }
            ParseSizeErrorKind::UnknownParameter { type_name, name } => {
                write!(f, "unknown parameter {name:?} for Type={type_name}")
            }
            ParseSizeErrorKind::MissingParameter { type_name, name } => {
                write!(f, "missing parameter {name} for Type={type_name}")
            }
            // The specification's own message is the whole story here.
            ParseSizeErrorKind::InvalidSpec { source } => Display::fmt(source, f),
        }
    }
}

impl Error for ParseSizeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self.inner.kind {
            ParseSizeErrorKind::InvalidInteger { source, .. } => Some(source),
            ParseSizeErrorKind::InvalidSpec { source } => Some(source),
            _ => None,
        }
    }
}

/// Error building a [`SizeSpec`] from parameters outside its domain.
///
/// Produced by the [`SizeSpec`] constructors, and by parsing when the
/// grammar is well formed but names such values.
#[derive(Debug)]
pub struct SizeSpecError {
    kind: SizeSpecErrorKind,
    #[expect(dead_code, reason = "surfaced through Debug output only")]
    backtrace: Backtrace,
}

#[derive(Debug)]
enum SizeSpecErrorKind {
    EmptyRange {
        start: u64,
        end: u64,
    },
    /// An excluded start of `u64::MAX`: no size lies above it.
    EmptyExclusiveStart,
    /// An excluded end of `0`: no size lies below it.
    EmptyExclusiveEnd,
    InvalidDistribution {
        type_name: &'static str,
        source: Box<dyn Error + Send + Sync>,
    },
}

impl SizeSpecError {
    fn new(kind: SizeSpecErrorKind) -> Self {
        Self {
            kind,
            backtrace: Backtrace::capture(),
        }
    }

    /// Returns `true` if a range contained no sizes: its start
    /// exceeded its end, or an exclusive bound at the edge of the
    /// 64-bit range excluded everything beyond it.
    #[must_use]
    pub fn is_empty_range(&self) -> bool {
        matches!(
            self.kind,
            SizeSpecErrorKind::EmptyRange { .. }
                | SizeSpecErrorKind::EmptyExclusiveStart
                | SizeSpecErrorKind::EmptyExclusiveEnd
        )
    }

    /// Returns `true` for parameters outside the sampler's domain.
    #[must_use]
    pub fn is_invalid_distribution(&self) -> bool {
        matches!(self.kind, SizeSpecErrorKind::InvalidDistribution { .. })
    }
}

impl Display for SizeSpecError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match &self.kind {
            SizeSpecErrorKind::EmptyRange { start, end } => {
                write!(f, "empty size range: start {start} exceeds end {end}")
            }
            SizeSpecErrorKind::EmptyExclusiveStart => {
                f.write_str("empty size range: excluded start u64::MAX admits no larger size")
            }
            SizeSpecErrorKind::EmptyExclusiveEnd => {
                f.write_str("empty size range: excluded end 0 admits no smaller size")
            }
            SizeSpecErrorKind::InvalidDistribution { type_name, source } => {
                write!(f, "invalid {type_name} distribution parameters: {source}")
            }
        }
    }
}

impl Error for SizeSpecError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self.kind {
            SizeSpecErrorKind::EmptyRange { .. }
            | SizeSpecErrorKind::EmptyExclusiveStart
            | SizeSpecErrorKind::EmptyExclusiveEnd => None,
            SizeSpecErrorKind::InvalidDistribution { source, .. } => Some(&**source),
        }
    }
}

/// Error drawing a size from a [`SizeChooser`].
///
/// A distribution produced a sample that is not finite. It happens while
/// generating, so the CLI reports it as a run failure
/// (exit 1) rather than a usage error.
#[derive(Debug)]
pub struct SampleError {
    #[expect(dead_code, reason = "surfaced through Debug output only")]
    backtrace: Backtrace,
}

impl SampleError {
    fn new() -> Self {
        Self {
            backtrace: Backtrace::capture(),
        }
    }
}

impl Display for SampleError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("file size sample is not finite (distribution overflow)")
    }
}

impl Error for SampleError {}

#[cfg(test)]
mod tests {
    use std::ops::Bound;

    use super::{SizeChooser, SizeSpec, parse_byte_size};

    fn spec(input: &str) -> SizeSpec {
        input
            .parse()
            .unwrap_or_else(|err| panic!("{input:?}: {err}"))
    }

    fn one_size(input: &str) -> u64 {
        spec(input).chooser().unwrap().next_size().unwrap()
    }

    #[test]
    fn byte_size_suffix_grammar() {
        // Two-character suffixes are case-insensitive.
        for (input, expected) in [
            ("8192", 8192),
            ("2kb", 2 * 1024),
            ("2KB", 2 * 1024),
            ("2Kb", 2 * 1024),
            ("1mb", 1024 * 1024),
            ("1MB", 1024 * 1024),
            ("1gb", 1 << 30),
            ("1tb", 1 << 40),
            ("0", 0),
        ] {
            assert_eq!(parse_byte_size(input).unwrap(), expected, "{input}");
        }
    }

    #[test]
    fn byte_size_rejects_single_letter_suffixes_and_junk() {
        // Single-letter suffixes such as `1k` and `100b` are usage errors.
        for input in ["1k", "100b", "bogus", "1xy", "", "kb", "-5", "4 096"] {
            let err = parse_byte_size(input).unwrap_err();
            assert!(err.is_invalid_integer(), "{input}");
        }
    }

    #[test]
    fn byte_size_rejects_overflow() {
        // 2^24 × 2^40 = 2^64, one past the representable range.
        let err = parse_byte_size("16777216tb").unwrap_err();
        assert!(err.is_overflow());
        assert_eq!(
            parse_byte_size("16777215tb").unwrap(),
            (1 << 40) * 16_777_215
        );
    }

    #[test]
    fn spec_shapes_parse_in_frozen_order() {
        assert_eq!(spec("4096"), SizeSpec::fixed(4096));
        assert_eq!(spec("2kb"), SizeSpec::fixed(2048));
        assert_eq!(spec("1kb-2kb"), SizeSpec::range(1024..=2048).unwrap());
        assert_eq!(
            spec("Type=normal,Mean=1kb,StdDev=0"),
            SizeSpec::normal(1024.0, 0.0).unwrap()
        );
        assert_eq!(
            spec("Type=gamma,Alpha=2,Beta=2mb"),
            SizeSpec::gamma(2.0, 2.0 * 1024.0 * 1024.0).unwrap()
        );
        assert_eq!(
            spec("Type=lognormal,Mean=16,StdDev=1"),
            SizeSpec::lognormal(16.0, 1.0).unwrap()
        );
    }

    #[test]
    fn spec_errors_match_the_behavior_matrix() {
        type Check = fn(&super::ParseSizeError) -> bool;
        // Each case is a pinned usage error (exit 2 at the CLI).
        let cases: [(&str, Check); 6] = [
            ("bogus", super::ParseSizeError::is_unknown_spec),
            ("1mb-2mb-3mb", super::ParseSizeError::is_malformed_range),
            ("Mean=1,StdDev=1", super::ParseSizeError::is_missing_type),
            ("Type=zipf,Mean=1", super::ParseSizeError::is_unknown_type),
            // Parameter names are validated at parse time.
            (
                "Type=normal,Mean=1024,StdDev=0,Foo=2",
                super::ParseSizeError::is_unknown_parameter,
            ),
            (
                "Type=normal,Mean=1024",
                super::ParseSizeError::is_missing_parameter,
            ),
        ];
        for (input, matches) in cases {
            let err = input.parse::<SizeSpec>().unwrap_err();
            assert!(matches(&err), "{input}: {err}");
        }
    }

    #[test]
    fn shorthand_item_without_equals_is_an_error() {
        let err = "Type=normal,Mean".parse::<SizeSpec>().unwrap_err();
        assert!(err.is_malformed_parameter());
        let err = "Type=normal,Mean=1=2".parse::<SizeSpec>().unwrap_err();
        assert!(err.is_malformed_parameter());
    }

    #[test]
    fn shorthand_duplicate_parameter_keeps_the_last_value() {
        // A repeated key silently overwrites its previous value.
        assert_eq!(
            spec("Type=normal,Mean=1,Mean=1kb,StdDev=0"),
            SizeSpec::normal(1024.0, 0.0).unwrap()
        );
    }

    #[test]
    fn degenerate_range_pins_both_endpoints_inclusive() {
        // Pinned by test_file_size_range_is_inclusive: randint(60, 60).
        let mut sizes = spec("60-60").chooser().unwrap();
        for _ in 0..16 {
            assert_eq!(sizes.next_size().unwrap(), 60);
        }
    }

    #[test]
    fn range_samples_stay_inside_the_bounds() {
        let mut sizes = spec("1kb-2kb").chooser().unwrap();
        for _ in 0..64 {
            let size = sizes.next_size().unwrap();
            assert!((1024..=2048).contains(&size), "{size}");
        }
    }

    #[test]
    #[expect(
        clippy::reversed_empty_ranges,
        reason = "the empty range is what this rejection test builds"
    )]
    fn empty_range_is_rejected_when_building_the_spec() {
        let err = SizeSpec::range(2048..=1024).unwrap_err();
        assert!(err.is_empty_range());

        // Parsing reports the same rejection, with the spec error as its
        // cause and its message.
        let err = "2kb-1kb".parse::<SizeSpec>().unwrap_err();
        let spec_err = err.invalid_spec_error().expect("the spec was rejected");
        assert!(spec_err.is_empty_range());
        assert_eq!(err.to_string(), spec_err.to_string());
    }

    #[test]
    fn exclusive_bounds_normalize_to_inclusive_bounds() {
        assert_eq!(
            SizeSpec::range(1024..2049).unwrap(),
            SizeSpec::range(1024..=2048).unwrap()
        );
        assert_eq!(
            SizeSpec::range((Bound::Excluded(1023), Bound::Included(2048))).unwrap(),
            SizeSpec::range(1024..=2048).unwrap()
        );
    }

    #[test]
    fn exclusive_bounds_at_the_edge_of_u64_are_empty() {
        // Saturating adjustment would accept these as 0..=0 and
        // u64::MAX..=u64::MAX, sampling the excluded value.
        let err = SizeSpec::range(..0).unwrap_err();
        assert!(err.is_empty_range());
        assert_eq!(
            err.to_string(),
            "empty size range: excluded end 0 admits no smaller size"
        );

        let err = SizeSpec::range(0..0).unwrap_err();
        assert!(err.is_empty_range());

        let err = SizeSpec::range((Bound::Excluded(u64::MAX), Bound::Unbounded)).unwrap_err();
        assert!(err.is_empty_range());
        assert_eq!(
            err.to_string(),
            "empty size range: excluded start u64::MAX admits no larger size"
        );
    }

    #[test]
    fn normal_with_zero_std_dev_is_exactly_the_mean() {
        // Pinned by test_normal_distribution_grammar.
        assert_eq!(one_size("Type=normal,Mean=1kb,StdDev=0"), 1024);
    }

    #[test]
    fn lognormal_parameters_stay_in_log_space() {
        // StdDev=0 gives int(e^8) == 2980 bytes, not 8.
        assert_eq!(one_size("Type=lognormal,Mean=8,StdDev=0"), 2980);
    }

    #[test]
    fn gamma_samples_are_finite_and_nonzero() {
        let mut sizes = spec("Type=gamma,Alpha=2,Beta=1kb").chooser().unwrap();
        for _ in 0..64 {
            // Post-processing guarantees a non-negative integer; the
            // generator, not the chooser, clamps to the 60-byte minimum.
            let _size = sizes.next_size().unwrap();
        }
    }

    #[test]
    fn gamma_rejects_non_positive_shape() {
        let err = SizeSpec::gamma(0.0, 1024.0).unwrap_err();
        assert!(err.is_invalid_distribution());
        // The sampler's own error stays reachable, not just its text.
        assert!(std::error::Error::source(&err).is_some());
    }

    #[test]
    fn samples_use_abs_after_truncation() {
        // A negative mean with zero deviation yields the positive
        // magnitude after truncation and absolute-value conversion.
        let mut sizes = SizeSpec::normal(-100.9, 0.0).unwrap().chooser().unwrap();
        assert_eq!(sizes.next_size().unwrap(), 100);
    }

    #[test]
    fn lognormal_overflow_is_a_reported_error() {
        // This input overflows the exponential; the sampler reports a
        // non-finite sample instead of crashing.
        let mut sizes = SizeSpec::lognormal(1e6, 0.0).unwrap().chooser().unwrap();
        let err = sizes.next_size().unwrap_err();
        assert_eq!(
            err.to_string(),
            "file size sample is not finite (distribution overflow)"
        );
    }

    #[test]
    fn custom_choosers_pass_values_through() {
        let mut sizes = SizeChooser::from_fn(|| 42);
        assert_eq!(sizes.next_size().unwrap(), 42);
        assert_eq!(format!("{sizes:?}"), "SizeChooser::Custom");
        assert_eq!(
            format!("{:?}", SizeChooser::fixed(7)),
            "SizeChooser::Fixed(7)"
        );
    }
}
