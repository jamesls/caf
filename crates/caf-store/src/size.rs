//! File-size grammar and selection for generation.
//!
//! The `--file-size` and `--max-disk-usage` grammar accepts plain byte
//! counts, two-character `kb`/`mb`/`gb`/`tb` suffixes (case-insensitive)
//! on an integer or decimal mantissa, inclusive `START-END` ranges, and
//! the `Type=…` distribution shorthand. [`SizeSpec`] is the parsed
//! grammar; [`SizeChooser`] draws one size per file from it.
//!
//! Every distribution is sampled inside a closed band. Its lower edge is
//! at least the 60-byte header and its upper edge is required, so no
//! sampled file is ever smaller or larger than the band. A draw outside
//! the band is discarded and redrawn, which leaves the named distribution
//! conditioned on the band rather than piling rejected draws onto its
//! edges. Seeded streams follow the CAF v3 generation
//! contract in `docs/generation.md`, including exact size sequences.
//! Unknown or missing distribution parameters are rejected at
//! parse time rather than causing generation to fail later.

use std::backtrace::Backtrace;
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};
use std::io;
use std::ops::{Bound, RangeBounds, RangeInclusive};
use std::str::FromStr;

use rand_chacha::ChaCha12Rng;
use rand_chacha::rand_core::SeedableRng;

use crate::generate::MIN_FILE_SIZE;
use crate::{GenerationSeed, random, sampling};

/// Multipliers for the two-character size suffixes. The grammar
/// matches them case-insensitively against the last two characters of a
/// token; single-letter suffixes (`1k`, `100b`) are errors. The spelling
/// here is the one error messages print.
const SUFFIXES: [(&str, u64); 4] = [
    ("KB", 1 << 10),
    ("MB", 1 << 20),
    ("GB", 1 << 30),
    ("TB", 1 << 40),
];

/// Two to the sixty-fourth: the first value a decimal mantissa times its
/// suffix may not reach, since it is one past `u64::MAX`.
const U64_RANGE: f64 = 18_446_744_073_709_551_616.0;

/// Require a conservative mass bound of half a percent before sampling.
/// This limits expected rejection work to at most 200 draws per file.
const MIN_SAMPLE_MASS: f64 = 0.005;

/// Parses a byte count with an optional `kb`/`mb`/`gb`/`tb` suffix.
///
/// This is the grammar `--max-disk-usage`, range endpoints, and byte-valued
/// distribution parameters share: `4096`, `2kb`, `1MB`, `1tb`, `1.5GB`.
/// Suffixes are case-insensitive. A mantissa without a `.` is an exact
/// unsigned integer. A mantissa with a `.` is ASCII digits around one
/// point, needs a suffix, is multiplied by it, and truncates toward zero
/// to whole bytes, so `0.1TB` is 109,951,162,777 bytes. Signs and
/// exponent notation (`1.0e-3MB`) are rejected, so a `-` in a
/// `--file-size` token is always the range separator.
///
/// # Examples
///
/// ```
/// use caf_store::parse_byte_size;
///
/// assert_eq!(parse_byte_size("4096")?, 4096);
/// assert_eq!(parse_byte_size("2Kb")?, 2048);
/// assert_eq!(parse_byte_size("1tb")?, 1 << 40);
/// assert_eq!(parse_byte_size("1.5MB")?, 1_572_864);
/// # Ok::<(), caf_store::ParseSizeError>(())
/// ```
///
/// # Errors
///
/// Returns a [`ParseSizeError`] if the token is not an unsigned integer
/// or a decimal with an optional known suffix, if a decimal has no
/// suffix, a sign, or an exponent, or if the suffixed value reaches the
/// 64-bit byte range.
pub fn parse_byte_size(value: impl AsRef<str>) -> Result<u64, ParseSizeError> {
    let value = value.as_ref();
    match split_suffix(value) {
        Some((mantissa, multiplier)) if mantissa.contains('.') => {
            parse_decimal(mantissa, multiplier, value)
        }
        Some((mantissa, multiplier)) => {
            let count = parse_integer(mantissa, value)?;
            count.checked_mul(multiplier).ok_or_else(|| overflow(value))
        }
        None if value.contains('.') => Err(ParseSizeError::new(
            ParseSizeErrorKind::DecimalWithoutSuffix {
                input: value.to_owned(),
            },
        )),
        None => parse_integer(value, value),
    }
}

/// Splits a trailing size suffix off `value`, if the last two characters
/// form one.
fn split_suffix(value: &str) -> Option<(&str, u64)> {
    let split = value.len().checked_sub(2)?;
    let (prefix, suffix) = value.split_at_checked(split)?;
    SUFFIXES
        .iter()
        .find(|(known, _)| known.eq_ignore_ascii_case(suffix))
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

/// Parses a decimal `mantissa` and scales it by `multiplier`, reporting
/// `input` (the full original token) on failure.
///
/// The mantissa is checked against the plain-decimal grammar before it
/// is handed to the float parser, which would otherwise accept signs,
/// exponents, and spellings such as `inf`.
fn parse_decimal(mantissa: &str, multiplier: u64, input: &str) -> Result<u64, ParseSizeError> {
    let invalid = || {
        ParseSizeError::new(ParseSizeErrorKind::InvalidDecimal {
            input: input.to_owned(),
        })
    };
    if !is_plain_decimal(mantissa) {
        return Err(invalid());
    }
    let mantissa: f64 = mantissa.parse().map_err(|_source| invalid())?;
    // Only a mantissa with hundreds of digits rounds to infinity, and
    // that is a value too large to hold, not a malformed one.
    if !mantissa.is_finite() {
        return Err(overflow(input));
    }
    #[expect(
        clippy::cast_precision_loss,
        reason = "suffix multipliers are powers of two far below 2^53"
    )]
    let bytes = mantissa * multiplier as f64;
    if bytes >= U64_RANGE {
        return Err(overflow(input));
    }
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "the product is non-negative and below 2^64, so the cast truncates toward zero"
    )]
    Ok(bytes as u64)
}

/// Reports whether `mantissa` is ASCII digits around exactly one `.`,
/// with at least one digit: `1.5`, `.5`, and `2.` qualify, while `+1.5`,
/// `1.0e-3`, `1.2.3`, and `.` do not.
fn is_plain_decimal(mantissa: &str) -> bool {
    let mut points = 0;
    let mut digits = 0;
    for byte in mantissa.bytes() {
        match byte {
            b'0'..=b'9' => digits += 1,
            b'.' => points += 1,
            _ => return false,
        }
    }
    points == 1 && digits > 0
}

fn overflow(input: &str) -> ParseSizeError {
    ParseSizeError::new(ParseSizeErrorKind::Overflow {
        input: input.to_owned(),
    })
}

/// Parses the dimensionless `Sigma` and `Alpha` values: a finite number
/// with no size suffix.
fn parse_number(name: &'static str, value: &str) -> Result<f64, ParseSizeError> {
    if split_suffix(value).is_some() {
        return Err(ParseSizeError::new(ParseSizeErrorKind::NotAByteSize {
            name,
        }));
    }
    let invalid = || {
        ParseSizeError::new(ParseSizeErrorKind::InvalidNumber {
            name,
            input: value.to_owned(),
        })
    };
    let number: f64 = value.parse().map_err(|_source| invalid())?;
    if !number.is_finite() {
        return Err(invalid());
    }
    Ok(number)
}

/// A parsed `--file-size` specification.
///
/// Parse one from the CLI grammar with [`FromStr`], or build one
/// directly with the constructors. Every constructor validates its
/// arguments, so a `SizeSpec` always describes a samplable distribution;
/// [`SizeSpec::chooser`] then draws the sampler's random seed. The
/// [`Display`] form is the canonical shorthand, which parses back to an
/// equal spec.
///
/// # Examples
///
/// ```
/// use caf_store::SizeSpec;
///
/// assert_eq!("4096".parse::<SizeSpec>()?, SizeSpec::fixed(4096));
/// assert_eq!("1kb-2kb".parse::<SizeSpec>()?, SizeSpec::range(1024..=2048)?);
/// assert_eq!(
///     "Type=lognormal,Median=1kb,Sigma=0.5,Max=1mb".parse::<SizeSpec>()?,
///     SizeSpec::lognormal(1024, 0.5, 60..=(1 << 20))?,
/// );
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct SizeSpec {
    kind: SpecKind,
}

/// The validated forms. Distributions keep the parameters the canonical
/// form prints; the check happens once, in the constructor, so a spec
/// always describes a samplable distribution.
#[derive(Clone, Copy, Debug, PartialEq)]
enum SpecKind {
    Fixed(u64),
    /// Invariant: `start <= end`.
    Range {
        start: u64,
        end: u64,
    },
    /// Invariant: `median >= 1` and `sigma` is finite and non-negative.
    LogNormal {
        median: u64,
        sigma: f64,
        band: Band,
    },
    /// Invariant: `alpha` is finite and positive; the sampler's scale is
    /// the band's lower edge.
    Pareto {
        alpha: f64,
        band: Band,
    },
}

/// The closed `[min, max]` band a distribution is sampled inside.
///
/// Invariant: `MIN_FILE_SIZE <= min < max`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Band {
    min: u64,
    max: u64,
}

impl Band {
    fn new(range: RangeInclusive<u64>) -> Result<Self, SizeSpecError> {
        let (min, max) = range.into_inner();
        if min < MIN_FILE_SIZE {
            return Err(SizeSpecError::new(SizeSpecErrorKind::BandTooLow));
        }
        if min >= max {
            return Err(SizeSpecError::new(SizeSpecErrorKind::EmptyBand {
                min,
                max,
            }));
        }
        Ok(Self { min, max })
    }

    /// Whether a truncated sample lies inside the band. The comparison
    /// is exact for every size below 2^53 bytes (8 PiB).
    #[expect(
        clippy::cast_precision_loss,
        reason = "sizes this tool generates are far below 2^53"
    )]
    fn contains(self, bytes: f64) -> bool {
        bytes >= self.min as f64 && bytes <= self.max as f64
    }
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

    /// Lognormal sizes with the given `median` in bytes and `sigma`, the
    /// standard deviation of the natural log of the size, sampled inside
    /// `band`.
    ///
    /// `sigma` is dimensionless: `1.0` puts 68% of files within a factor
    /// of e (2.72) of the median and 95% within a factor of e² (7.4);
    /// `0.0` makes every sample the median. The median may lie outside
    /// the band, which then selects one tail of the distribution. A band
    /// with less than 0.5% conservatively bounded probability mass is not
    /// a construction error; its first draw fails with a [`SampleError`].
    ///
    /// # Examples
    ///
    /// ```
    /// use caf_store::SizeSpec;
    ///
    /// let spec = SizeSpec::lognormal(1 << 20, 1.0, 60..=(1 << 30))?;
    /// assert_eq!(spec, "Type=lognormal,Median=1MB,Sigma=1,Max=1GB".parse()?);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns a [`SizeSpecError`] if `median` is zero, `sigma` is
    /// negative or not finite, the band starts below the 60-byte header,
    /// or the band does not hold at least two sizes.
    pub fn lognormal(
        median: u64,
        sigma: f64,
        band: RangeInclusive<u64>,
    ) -> Result<Self, SizeSpecError> {
        if median == 0 {
            return Err(SizeSpecError::invalid_parameter("Median", "at least 1"));
        }
        if !(sigma.is_finite() && sigma >= 0.0) {
            return Err(SizeSpecError::invalid_parameter("Sigma", "at least zero"));
        }
        let band = Band::new(band)?;
        Ok(Self {
            kind: SpecKind::LogNormal {
                median,
                sigma,
                band,
            },
        })
    }

    /// Pareto sizes with shape `alpha`, sampled inside `band`, whose start
    /// is also the scale parameter: the smallest possible size.
    ///
    /// Smaller `alpha` means a heavier tail. Before truncation the
    /// fraction of files larger than `x` is `(min / x) ^ alpha`, so with
    /// `alpha = 1.2` and a 4 KiB start half the files are under 7.1 KiB
    /// while about one in 800 exceeds 1 MiB.
    ///
    /// # Examples
    ///
    /// ```
    /// use caf_store::SizeSpec;
    ///
    /// let spec = SizeSpec::pareto(1.2, 4096..=(1 << 30))?;
    /// assert_eq!(spec, "Type=pareto,Min=4KB,Max=1GB,Alpha=1.2".parse()?);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns a [`SizeSpecError`] if `alpha` is not a finite number
    /// greater than zero, the band starts below the 60-byte header, or
    /// the band does not hold at least two sizes.
    pub fn pareto(alpha: f64, band: RangeInclusive<u64>) -> Result<Self, SizeSpecError> {
        if !(alpha.is_finite() && alpha > 0.0) {
            return Err(SizeSpecError::invalid_parameter(
                "Alpha",
                "greater than zero",
            ));
        }
        let band = Band::new(band)?;
        Ok(Self {
            kind: SpecKind::Pareto { alpha, band },
        })
    }

    /// Parses the `--file-size` grammar, trying shapes in this order:
    /// plain integer, distribution shorthand (contains
    /// `,`), inclusive range (contains `-`), then suffixed or decimal
    /// fixed size.
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
        // A bare decimal such as `1.5` is routed to the byte grammar so
        // the error says a suffix is needed, not that the shape is unknown.
        if split_suffix(input).is_some() || input.parse::<f64>().is_ok() {
            return Ok(Self::fixed(parse_byte_size(input)?));
        }
        Err(ParseSizeError::new(ParseSizeErrorKind::UnknownSpec {
            input: input.to_owned(),
        }))
    }

    /// Check mass deterministically, before the chooser can return any size.
    #[expect(
        clippy::cast_precision_loss,
        reason = "distribution sampling uses floating-point byte counts"
    )]
    fn supports_sampling(&self) -> bool {
        let mass = match self.kind {
            SpecKind::Fixed(_) | SpecKind::Range { .. } => return true,
            SpecKind::LogNormal {
                median,
                sigma,
                band,
            } => {
                if sigma == 0.0 {
                    // The zero-sigma sampler returns the exact integer median.
                    return band.min <= median && median <= band.max;
                }
                // Include the fractional bytes that truncate to the upper edge.
                let lower = libm::log(band.min as f64 / median as f64) / sigma;
                let upper = libm::log((band.max as f64 + 1.0) / median as f64) / sigma;
                normal_mass_lower_bound(lower, upper)
            }
            SpecKind::Pareto { alpha, band, .. } => {
                // -expm1 avoids cancellation for small alpha or narrow bands.
                -libm::expm1(alpha * libm::log(band.min as f64 / (band.max as f64 + 1.0)))
            }
        };
        mass >= MIN_SAMPLE_MASS
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
        if let SpecKind::Fixed(bytes) = self.kind {
            return Ok(SizeChooser::fixed(bytes));
        }
        Ok(self.chooser_with_rng(os_seeded_rng()?))
    }

    /// Returns a CAF v3'size sampler without drawing operating-system randomness.
    ///
    /// # Examples
    ///
    /// ```
    /// use caf_store::{GenerationSeed, SizeSpec};
    /// let seed = GenerationSeed::new("example")?;
    /// let spec = SizeSpec::range(60..=100)?;
    /// let mut first = spec.chooser_seeded(&seed);
    /// let mut second = spec.chooser_seeded(&seed);
    /// assert_eq!(first.next_size()?, second.next_size()?);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn chooser_seeded(&self, seed: &GenerationSeed) -> SizeChooser {
        self.chooser_with_rng(ChaCha12Rng::from_seed(seed.size_rng_seed()))
    }

    #[expect(
        clippy::cast_precision_loss,
        reason = "distribution sampling uses floating-point byte counts"
    )]
    fn chooser_with_rng(&self, rng: ChaCha12Rng) -> SizeChooser {
        let kind = match self.kind {
            SpecKind::Fixed(bytes) => ChooserKind::Fixed(bytes),
            SpecKind::Range { start, end } => ChooserKind::Range { start, end, rng },
            SpecKind::LogNormal {
                median,
                sigma,
                band,
            } => ChooserKind::Sampled {
                spec: self.clone(),
                sampler: Sampler::LogNormal { median, sigma },
                supported: self.supports_sampling(),
                band,
                rng,
            },
            SpecKind::Pareto { alpha, band } => ChooserKind::Sampled {
                spec: self.clone(),
                sampler: Sampler::Pareto {
                    min: band.min as f64,
                    inv_neg_alpha: -1.0 / alpha,
                },
                supported: self.supports_sampling(),
                band,
                rng,
            },
        };
        SizeChooser { kind }
    }
}

impl FromStr for SizeSpec {
    type Err = ParseSizeError;

    fn from_str(input: &str) -> Result<Self, ParseSizeError> {
        Self::parse(input)
    }
}

/// The canonical shorthand: byte values as integers, defaults filled
/// in, and `Sigma` and `Alpha` in Rust's default `f64` formatting, so
/// `2` prints as `2` and `1.5` as `1.5`. Parsing the output gives back
/// an equal spec.
impl Display for SizeSpec {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self.kind {
            SpecKind::Fixed(bytes) => write!(f, "{bytes}"),
            SpecKind::Range { start, end } => write!(f, "{start}-{end}"),
            SpecKind::LogNormal {
                median,
                sigma,
                band,
                ..
            } => write!(
                f,
                "Type=lognormal,Median={median},Sigma={sigma},Min={},Max={}",
                band.min, band.max
            ),
            SpecKind::Pareto { alpha, band, .. } => write!(
                f,
                "Type=pareto,Min={},Max={},Alpha={alpha}",
                band.min, band.max
            ),
        }
    }
}

/// Keys each distribution accepts, in the order the canonical form
/// prints them.
const LOGNORMAL_KEYS: [&str; 4] = ["Median", "Sigma", "Min", "Max"];
const PARETO_KEYS: [&str; 3] = ["Min", "Max", "Alpha"];

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
        "lognormal" => {
            let params = Params::new("lognormal", &LOGNORMAL_KEYS, &params)?;
            let median = params.bytes("Median")?;
            let sigma = params.number("Sigma")?;
            let max = params.bytes("Max")?;
            let min = params.optional_bytes("Min")?.unwrap_or(MIN_FILE_SIZE);
            SizeSpec::lognormal(median, sigma, min..=max)
        }
        "pareto" => {
            let params = Params::new("pareto", &PARETO_KEYS, &params)?;
            let min = params.optional_bytes("Min")?.unwrap_or(MIN_FILE_SIZE);
            let max = params.bytes("Max")?;
            let alpha = params.number("Alpha")?;
            SizeSpec::pareto(alpha, min..=max)
        }
        "gamma" => {
            return Err(ParseSizeError::new(ParseSizeErrorKind::RemovedType {
                name: "gamma",
            }));
        }
        "normal" => {
            return Err(ParseSizeError::new(ParseSizeErrorKind::RemovedType {
                name: "normal",
            }));
        }
        other => {
            return Err(ParseSizeError::new(ParseSizeErrorKind::UnknownType {
                name: other.to_owned(),
            }));
        }
    };
    spec.map_err(ParseSizeError::invalid_spec)
}

/// The `Key=Value` items of one shorthand, checked against the keys its
/// distribution accepts. A repeated key keeps its last value.
struct Params<'a> {
    type_name: &'static str,
    items: &'a [(&'a str, &'a str)],
}

impl<'a> Params<'a> {
    /// Rejects the first key `accepted` does not list.
    fn new(
        type_name: &'static str,
        accepted: &'static [&'static str],
        items: &'a [(&'a str, &'a str)],
    ) -> Result<Self, ParseSizeError> {
        if let Some(&(name, _)) = items.iter().find(|(name, _)| !accepted.contains(name)) {
            return Err(ParseSizeError::new(ParseSizeErrorKind::UnknownParameter {
                type_name,
                name: name.to_owned(),
                accepted,
            }));
        }
        Ok(Self { type_name, items })
    }

    fn value(&self, name: &str) -> Option<&'a str> {
        self.items
            .iter()
            .rev()
            .find(|(key, _)| *key == name)
            .map(|&(_, value)| value)
    }

    fn required(&self, name: &'static str) -> Result<&'a str, ParseSizeError> {
        self.value(name).ok_or_else(|| {
            ParseSizeError::new(ParseSizeErrorKind::MissingParameter {
                type_name: self.type_name,
                name,
            })
        })
    }

    /// A required byte-valued key.
    fn bytes(&self, name: &'static str) -> Result<u64, ParseSizeError> {
        parse_byte_size(self.required(name)?)
    }

    /// An optional byte-valued key.
    fn optional_bytes(&self, name: &'static str) -> Result<Option<u64>, ParseSizeError> {
        self.value(name).map(parse_byte_size).transpose()
    }

    /// A required dimensionless key.
    fn number(&self, name: &'static str) -> Result<f64, ParseSizeError> {
        parse_number(name, self.required(name)?)
    }
}

/// Bound normal mass from below using rectangles under its density.
/// Ignore tails beyond four standard deviations and partition the rest
/// into 64 intervals. The density minimum is at the endpoint furthest
/// from zero; summing those rectangles cannot overestimate the mass.
/// This deliberately rejects borderline bands rather than relying on
/// random trial draws to decide whether a band is supported.
fn normal_mass_lower_bound(lower: f64, upper: f64) -> f64 {
    let mut mass = 0.0;
    for index in 0..64 {
        let left = lower.max(-4.0 + f64::from(index) / 8.0);
        let right = upper.min(-4.0 + f64::from(index + 1) / 8.0);
        if left < right {
            let furthest = left.abs().max(right.abs());
            let density =
                libm::exp(-0.5 * furthest * furthest) / libm::sqrt(2.0 * std::f64::consts::PI);
            mass += (right - left) * density;
        }
    }
    mass
}

/// Seeds the sampling RNG from the operating-system random source.
fn os_seeded_rng() -> io::Result<ChaCha12Rng> {
    let mut seed = <ChaCha12Rng as SeedableRng>::Seed::default();
    random::fill(&mut seed)?;
    Ok(ChaCha12Rng::from_seed(seed))
}

/// Draws one file size per call from a [`SizeSpec`] (or a custom
/// closure via [`SizeChooser::from_fn`]).
///
/// Fixed and range sizes are returned as they are; the generator clamps
/// any value below the 60-byte header up to it. Distribution samples are
/// truncated toward zero and redrawn until one lands inside the spec's
/// band, so they arrive already clamped. Custom choosers may return any
/// value; no band applies to them.
pub struct SizeChooser {
    kind: ChooserKind,
}

enum ChooserKind {
    Fixed(u64),
    Range {
        start: u64,
        end: u64,
        rng: ChaCha12Rng,
    },
    Sampled {
        /// The spec the sampler came from, for the unsupported-band error.
        spec: SizeSpec,
        sampler: Sampler,
        supported: bool,
        band: Band,
        rng: ChaCha12Rng,
    },
    Custom(Box<dyn FnMut() -> u64 + Send>),
}

/// The distribution behind a sampled chooser.
#[derive(Clone, Copy, Debug)]
enum Sampler {
    /// `median × e^(sigma × z)` for a standard normal `z`. This is the
    /// lognormal with log-space mean `ln(median)`, computed without the
    /// round trip through the logarithm, so `sigma = 0` gives the median
    /// exactly instead of one bit below it.
    LogNormal {
        median: u64,
        sigma: f64,
    },
    Pareto {
        min: f64,
        inv_neg_alpha: f64,
    },
}

impl Sampler {
    #[expect(
        clippy::cast_precision_loss,
        reason = "the median is a byte count; the sampler works in floating point"
    )]
    fn sample(self, rng: &mut impl rand_chacha::rand_core::RngCore) -> f64 {
        match self {
            Self::LogNormal { median, sigma } => {
                let z = sampling::normal(rng);
                median as f64 * libm::exp(sigma * z)
            }
            Self::Pareto { min, inv_neg_alpha } => sampling::pareto(rng, min, inv_neg_alpha),
        }
    }
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

    /// Returns the one size this chooser always selects, when it is fixed.
    pub(crate) fn fixed_size(&self) -> Option<u64> {
        match &self.kind {
            ChooserKind::Fixed(bytes) => Some(*bytes),
            ChooserKind::Range { .. } | ChooserKind::Sampled { .. } | ChooserKind::Custom(_) => {
                None
            }
        }
    }

    /// Returns the size in bytes for the next file.
    ///
    /// # Errors
    ///
    /// Returns a [`SampleError`] on the first and every subsequent call
    /// if the band lacks a conservative probability mass of at least 0.5%.
    pub fn next_size(&mut self) -> Result<u64, SampleError> {
        match &mut self.kind {
            ChooserKind::Fixed(bytes) => Ok(*bytes),
            ChooserKind::Range { start, end, rng } => Ok(sampling::uniform(rng, *start, *end)),
            ChooserKind::Sampled {
                spec,
                sampler,
                supported,
                band,
                rng,
            } => {
                if !*supported {
                    return Err(SampleError::unsupported_band(spec.clone(), *band));
                }
                Ok(sample_in_band(*sampler, *band, rng))
            }
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
            ChooserKind::Sampled { spec, .. } => write!(f, "SizeChooser::Sampled({spec})"),
            ChooserKind::Custom(_) => f.write_str("SizeChooser::Custom"),
        }
    }
}

/// Draws from a supported band until a truncated sample lands inside it.
/// Preflight bounds expected work; no per-file retry limit can fail later
/// and leave a partially generated store.
fn sample_in_band(
    sampler: Sampler,
    band: Band,
    rng: &mut impl rand_chacha::rand_core::RngCore,
) -> u64 {
    if let Sampler::LogNormal { median, sigma: 0.0 } = sampler {
        return median;
    }
    loop {
        let sample = sampler.sample(rng);
        // A NaN compares false against both edges and would otherwise
        // pass the band test, so finiteness comes first.
        if !sample.is_finite() {
            continue;
        }
        // Truncating before the comparison lets a draw of `max + 0.5`
        // count as `max` instead of being rejected.
        let bytes = sample.trunc();
        if !band.contains(bytes) {
            continue;
        }
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "the value is a whole number inside a u64 band"
        )]
        return bytes as u64;
    }
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
    /// A decimal mantissa that is not ASCII digits around one point.
    InvalidDecimal {
        input: String,
    },
    /// A decimal mantissa with nothing to scale it by.
    DecimalWithoutSuffix {
        input: String,
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
    /// `Type=gamma` or `Type=normal`, which this grammar no longer has.
    RemovedType {
        name: &'static str,
    },
    MalformedParameter {
        item: String,
    },
    UnknownParameter {
        type_name: &'static str,
        name: String,
        accepted: &'static [&'static str],
    },
    MissingParameter {
        type_name: &'static str,
        name: &'static str,
    },
    /// A size suffix on a dimensionless key.
    NotAByteSize {
        name: &'static str,
    },
    /// A dimensionless key whose value is not a finite number.
    InvalidNumber {
        name: &'static str,
        input: String,
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

    /// Returns `true` if a decimal token had no suffix to scale it, or
    /// was negative or not finite.
    #[must_use]
    pub fn is_invalid_decimal(&self) -> bool {
        matches!(
            self.inner.kind,
            ParseSizeErrorKind::InvalidDecimal { .. }
                | ParseSizeErrorKind::DecimalWithoutSuffix { .. }
        )
    }

    /// Returns `true` if a suffixed value reached 64 bits.
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

    /// Returns `true` for `Type=gamma` or `Type=normal`, whose messages
    /// name the replacement.
    #[must_use]
    pub fn is_removed_type(&self) -> bool {
        matches!(self.inner.kind, ParseSizeErrorKind::RemovedType { .. })
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

    /// Returns `true` if a dimensionless key such as `Sigma` or `Alpha`
    /// carried a size suffix.
    #[must_use]
    pub fn is_not_a_byte_size(&self) -> bool {
        matches!(self.inner.kind, ParseSizeErrorKind::NotAByteSize { .. })
    }

    /// Returns `true` if a dimensionless key was not a finite number.
    #[must_use]
    pub fn is_invalid_number(&self) -> bool {
        matches!(self.inner.kind, ParseSizeErrorKind::InvalidNumber { .. })
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
            ParseSizeErrorKind::InvalidDecimal { input } => write!(
                f,
                "invalid size specifier {input:?}: a decimal is digits around one point with no \
                 sign or exponent, such as 1.5MB"
            ),
            ParseSizeErrorKind::DecimalWithoutSuffix { input } => write!(
                f,
                "invalid size specifier {input:?}: a decimal needs a size suffix such as 1.5MB"
            ),
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
            ParseSizeErrorKind::UnknownType { name } => {
                write!(f, "unknown Type {name:?}, must be one of: lognormal,pareto")
            }
            ParseSizeErrorKind::RemovedType { name: "gamma" } => f.write_str(
                "Type gamma was removed; use Type=pareto,Min=<bytes>,Max=<bytes>,Alpha=<shape> \
                 for a heavy tail",
            ),
            ParseSizeErrorKind::RemovedType { name } => write!(
                f,
                "Type {name} was removed; use a range such as 19MB-21MB, or \
                 Type=lognormal,Median=<bytes>,Sigma=<number>,Max=<bytes> with Sigma set to \
                 StdDev divided by Mean"
            ),
            ParseSizeErrorKind::MalformedParameter { item } => {
                write!(f, "malformed size parameter {item:?}: expected Key=Value")
            }
            ParseSizeErrorKind::UnknownParameter {
                type_name,
                name,
                accepted,
            } => {
                write!(
                    f,
                    "unknown parameter {name:?} for Type={type_name}; {type_name} takes "
                )?;
                // The old log-space grammar is the likely source of a
                // `Mean` key, so that one names its translation.
                if *type_name == "lognormal" && name == "Mean" {
                    return f.write_str(
                        "Median=<bytes>,Sigma=<number>,Max=<bytes> \
                         (Median=8.5MB matches the old Mean=16)",
                    );
                }
                for (index, key) in accepted.iter().enumerate() {
                    if index > 0 {
                        f.write_str(", ")?;
                    }
                    f.write_str(key)?;
                }
                Ok(())
            }
            ParseSizeErrorKind::MissingParameter { type_name, name } => {
                write!(f, "missing parameter {name} for Type={type_name}")
            }
            ParseSizeErrorKind::NotAByteSize { name } => {
                write!(f, "{name} is a plain number, not a byte size")
            }
            ParseSizeErrorKind::InvalidNumber { name, input } => {
                write!(f, "invalid {name} value {input:?}: not a finite number")
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
    /// A band starting below the 60-byte header.
    BandTooLow,
    /// A band holding at most one size.
    EmptyBand {
        min: u64,
        max: u64,
    },
    /// A distribution parameter outside the sampler's domain.
    InvalidParameter {
        name: &'static str,
        requirement: &'static str,
    },
}

impl SizeSpecError {
    fn new(kind: SizeSpecErrorKind) -> Self {
        Self {
            kind,
            backtrace: Backtrace::capture(),
        }
    }

    fn invalid_parameter(name: &'static str, requirement: &'static str) -> Self {
        Self::new(SizeSpecErrorKind::InvalidParameter { name, requirement })
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

    /// Returns `true` if a distribution's band started below the
    /// 60-byte header.
    #[must_use]
    pub fn is_band_too_low(&self) -> bool {
        matches!(self.kind, SizeSpecErrorKind::BandTooLow)
    }

    /// Returns `true` if a distribution's band did not hold at least two
    /// sizes: its lower edge was not strictly below its upper edge.
    #[must_use]
    pub fn is_empty_band(&self) -> bool {
        matches!(self.kind, SizeSpecErrorKind::EmptyBand { .. })
    }

    /// Returns `true` for a parameter outside the sampler's domain.
    #[must_use]
    pub fn is_invalid_distribution(&self) -> bool {
        matches!(self.kind, SizeSpecErrorKind::InvalidParameter { .. })
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
            SizeSpecErrorKind::BandTooLow => write!(
                f,
                "Min must be at least {MIN_FILE_SIZE} bytes, the header size"
            ),
            SizeSpecErrorKind::EmptyBand { min, max } if min == max => write!(
                f,
                "size band {min}..={max} holds one size; use --file-size {} instead",
                ShortSize(*min)
            ),
            SizeSpecErrorKind::EmptyBand { min, max } => {
                write!(f, "size band {min}..={max} is empty: Min exceeds Max")
            }
            SizeSpecErrorKind::InvalidParameter { name, requirement } => {
                write!(f, "{name} must be {requirement}")
            }
        }
    }
}

impl Error for SizeSpecError {}

/// Renders a byte count with the largest suffix that divides it exactly,
/// so `1048576` prints as `1MB` and `4097` as `4097`.
struct ShortSize(u64);

impl Display for ShortSize {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let bytes = self.0;
        let suffixed = SUFFIXES
            .iter()
            .rev()
            .find(|(_, multiplier)| bytes != 0 && bytes % multiplier == 0);
        match suffixed {
            Some((suffix, multiplier)) => write!(f, "{}{suffix}", bytes / multiplier),
            None => write!(f, "{bytes}"),
        }
    }
}

/// Error drawing a size from a [`SizeChooser`].
///
/// The band lacks a conservative probability mass of at least 0.5%.
/// It happens while generating, so the CLI reports
/// it as a run failure (exit 1) rather than a usage error; it surfaces
/// on the first file, before anything is written.
#[derive(Debug)]
pub struct SampleError {
    inner: Box<SampleErrorInner>,
}

/// Boxed so `Result<u64, SampleError>` stays small on the success path.
#[derive(Debug)]
struct SampleErrorInner {
    spec: SizeSpec,
    band: Band,
    #[expect(dead_code, reason = "surfaced through Debug output only")]
    backtrace: Backtrace,
}

impl SampleError {
    fn unsupported_band(spec: SizeSpec, band: Band) -> Self {
        Self {
            inner: Box::new(SampleErrorInner {
                spec,
                band,
                backtrace: Backtrace::capture(),
            }),
        }
    }

    /// The specification whose band cannot be sampled reliably.
    #[must_use]
    pub fn spec(&self) -> &SizeSpec {
        &self.inner.spec
    }

    /// The unsupported band.
    #[must_use]
    pub fn band(&self) -> RangeInclusive<u64> {
        self.inner.band.min..=self.inner.band.max
    }
}

impl Display for SampleError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let Band { min, max } = self.inner.band;
        write!(
            f,
            "insufficient probability mass within {min}..={max} bytes for {}",
            self.inner.spec
        )
    }
}

impl Error for SampleError {}

#[cfg(test)]
mod tests {
    use std::ops::Bound;

    use proptest::prelude::*;

    use super::{ParseSizeError, SizeChooser, SizeSpec, SizeSpecError, parse_byte_size};

    fn spec(input: &str) -> SizeSpec {
        input
            .parse()
            .unwrap_or_else(|err| panic!("{input:?}: {err}"))
    }

    fn one_size(input: &str) -> u64 {
        spec(input).chooser().unwrap().next_size().unwrap()
    }

    #[test]
    fn seeded_v3_size_sequences() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../../../tests/golden/generation-v3.json"))
                .expect("valid generation vectors");
        let seed = crate::GenerationSeed::new(vectors["seed"].as_str().expect("seed text"))
            .expect("nonempty seed");
        for sequence in vectors["sequences"].as_array().expect("sequences") {
            let spec = spec(sequence["spec"].as_str().expect("size spec"));
            let mut chooser = spec.chooser_seeded(&seed);
            for expected in sequence["sizes"].as_array().expect("expected sizes") {
                assert_eq!(
                    chooser.next_size().expect("supported band"),
                    expected.as_u64().expect("size"),
                    "{spec}"
                );
            }
        }
    }

    #[test]
    fn sampling_truncates_before_testing_the_band_and_rejects_infinity() {
        use super::{Band, Sampler, sample_in_band};
        use crate::sampling::tests::Words;

        let band = Band { min: 61, max: 81 };
        let mut words = Words(vec![((3_u64 << 51) - 1) << 11].into_iter());
        // U=3/4 gives 81.333..., which must be accepted as 81.
        assert_eq!(
            sample_in_band(
                Sampler::Pareto {
                    min: 61.0,
                    inv_neg_alpha: -1.0
                },
                band,
                &mut words
            ),
            81
        );
        let mut words = Words(vec![0, u64::MAX].into_iter());
        assert_eq!(
            sample_in_band(
                Sampler::Pareto {
                    min: 61.0,
                    inv_neg_alpha: -f64::MAX
                },
                band,
                &mut words
            ),
            61
        );
        assert_eq!(words.0.next(), None);
    }

    #[test]
    fn zero_sigma_preserves_integer_precision_and_consumes_no_draws() {
        use super::{Band, Sampler, sample_in_band};
        use crate::sampling::tests::Words;

        let mut words = Words(Vec::new().into_iter());
        for median in [60, (1 << 53) + 1, u64::MAX] {
            let spec = SizeSpec::lognormal(median, 0.0, 60..=u64::MAX).expect("valid band");
            assert!(spec.supports_sampling());
            assert_eq!(
                sample_in_band(
                    Sampler::LogNormal { median, sigma: 0.0 },
                    Band {
                        min: 60,
                        max: u64::MAX
                    },
                    &mut words
                ),
                median
            );
        }
    }

    #[test]
    fn zero_sigma_checks_integer_band_edges() {
        let seed = crate::GenerationSeed::new("zero sigma").expect("nonempty seed");
        for (median, band) in [
            ((1 << 53) + 1, 60..=(1 << 53)),
            (1 << 53, ((1 << 53) + 1)..=u64::MAX),
            (u64::MAX, 60..=(u64::MAX - 1)),
            (u64::MAX - 2, (u64::MAX - 1)..=u64::MAX),
        ] {
            let spec = SizeSpec::lognormal(median, 0.0, band).expect("valid band");
            for mut chooser in [
                spec.chooser().expect("OS randomness"),
                spec.chooser_seeded(&seed),
            ] {
                chooser
                    .next_size()
                    .expect_err("integer median lies outside the band");
            }
        }

        for (median, band) in [
            ((1 << 53) + 1, ((1 << 53) + 1)..=((1 << 53) + 2)),
            ((1 << 53) + 1, (1 << 53)..=((1 << 53) + 1)),
            (u64::MAX - 1, (u64::MAX - 1)..=u64::MAX),
            (u64::MAX, (u64::MAX - 1)..=u64::MAX),
        ] {
            let spec = SizeSpec::lognormal(median, 0.0, band).expect("valid band");
            for mut chooser in [
                spec.chooser().expect("OS randomness"),
                spec.chooser_seeded(&seed),
            ] {
                assert_eq!(
                    chooser.next_size().expect("median lies on a band edge"),
                    median
                );
            }
        }
    }

    fn parse_error(input: &str) -> ParseSizeError {
        input
            .parse::<SizeSpec>()
            .expect_err("the specification is rejected")
    }

    #[test]
    fn byte_size_suffix_grammar() {
        // Two-character suffixes are case-insensitive; a decimal
        // mantissa is scaled by its suffix and truncated to whole bytes.
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
            ("1.5KB", 1536),
            ("1.5mb", 1_572_864),
            ("0.25GB", 1 << 28),
            ("0.1TB", 109_951_162_777),
            (".5KB", 512),
            ("2.0kb", 2048),
            ("0.0001KB", 0),
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
    fn decimal_byte_sizes_need_a_suffix_and_a_finite_mantissa() {
        let err = parse_byte_size("1.5").unwrap_err();
        assert!(err.is_invalid_decimal());
        assert_eq!(
            err.to_string(),
            "invalid size specifier \"1.5\": a decimal needs a size suffix such as 1.5MB"
        );
        // The same rejection reaches `--file-size 1.5`.
        assert!(parse_error("1.5").is_invalid_decimal());

        // Signs and exponents are rejected along with malformed
        // mantissas, so `1.0e-3MB` never reads as a range endpoint or a
        // fixed size. `1e3MB` has no point and fails as an integer.
        for input in [
            "-1.5MB",
            "+1.5MB",
            "1.2.3MB",
            ".MB",
            "1.0e400MB",
            "1.0e-3MB",
            "1.0E3MB",
            "x.yMB",
            "1.5 MB",
            "inf.MB",
            "1.5\u{661}MB",
        ] {
            let err = parse_byte_size(input).unwrap_err();
            assert!(err.is_invalid_decimal(), "{input}: {err}");
            assert_eq!(
                err.to_string(),
                format!(
                    "invalid size specifier {input:?}: a decimal is digits around one point with \
                     no sign or exponent, such as 1.5MB"
                )
            );
        }
        assert!(parse_byte_size("1e3MB").unwrap_err().is_invalid_integer());
        assert!(parse_byte_size("1e-3MB").unwrap_err().is_invalid_integer());
    }

    #[test]
    fn exponent_notation_is_rejected_consistently_across_parsers() {
        // The same token fails the same way as a `--file-size` fixed
        // size, as either range endpoint, and as a distribution parameter.
        assert!(parse_error("1.0e-3MB").is_invalid_decimal());
        assert!(parse_error("1.0e3MB-5MB").is_invalid_decimal());
        assert!(parse_error("1MB-1.0e3MB").is_invalid_decimal());
        // A negative exponent inside a range splits on its sign and is
        // reported as a malformed range; it is never a fixed size.
        assert!(parse_error("1.0e-3MB-5MB").is_malformed_range());
        assert!(parse_error("1MB-1.0e-3MB").is_malformed_range());
        assert!(parse_error("Type=lognormal,Median=1.0e-3MB,Sigma=1,Max=1MB").is_invalid_decimal());
        // Bare `1.0e3` reaches the byte grammar and asks for a suffix.
        assert!(parse_error("1.0e3").is_invalid_decimal());
    }

    #[test]
    fn decimal_mantissa_rounding_to_infinity_is_an_overflow() {
        let input = format!("1{}.0KB", "0".repeat(400));
        let err = parse_byte_size(&input).unwrap_err();
        assert!(err.is_overflow(), "{err}");
    }

    #[test]
    fn byte_size_rejects_overflow() {
        // 2^24 × 2^40 = 2^64, one past the representable range, for an
        // integer or a decimal mantissa alike.
        let err = parse_byte_size("16777216tb").unwrap_err();
        assert!(err.is_overflow());
        assert_eq!(
            parse_byte_size("16777215tb").unwrap(),
            (1 << 40) * 16_777_215
        );
        let err = parse_byte_size("16777216.0tb").unwrap_err();
        assert!(err.is_overflow());
        // (2^24 - 0.5) × 2^40 = 2^64 - 2^39, the largest decimal below the edge.
        assert_eq!(
            parse_byte_size("16777215.5tb").unwrap(),
            u64::MAX - (1 << 39) + 1
        );
    }

    #[test]
    fn spec_shapes_parse_in_frozen_order() {
        assert_eq!(spec("4096"), SizeSpec::fixed(4096));
        assert_eq!(spec("2kb"), SizeSpec::fixed(2048));
        assert_eq!(spec("1.5kb"), SizeSpec::fixed(1536));
        assert_eq!(spec("1kb-2kb"), SizeSpec::range(1024..=2048).unwrap());
        assert_eq!(spec("1.5kb-2.5kb"), SizeSpec::range(1536..=2560).unwrap());
        assert_eq!(
            spec("Type=lognormal,Median=1kb,Sigma=0,Max=2kb"),
            SizeSpec::lognormal(1024, 0.0, 60..=2048).unwrap()
        );
        assert_eq!(
            spec("Type=lognormal,Median=1MB,Sigma=1.5,Min=4KB,Max=1GB"),
            SizeSpec::lognormal(1 << 20, 1.5, 4096..=(1 << 30)).unwrap()
        );
        assert_eq!(
            spec("Type=pareto,Min=4KB,Max=1GB,Alpha=1.2"),
            SizeSpec::pareto(1.2, 4096..=(1 << 30)).unwrap()
        );
    }

    #[test]
    fn spec_errors_match_the_behavior_matrix() {
        type Check = fn(&ParseSizeError) -> bool;
        // Each case is a pinned usage error (exit 2 at the CLI).
        let cases: [(&str, Check); 9] = [
            ("bogus", ParseSizeError::is_unknown_spec),
            ("1mb-2mb-3mb", ParseSizeError::is_malformed_range),
            ("Median=1,Sigma=1", ParseSizeError::is_missing_type),
            ("Type=zipf,Mean=1", ParseSizeError::is_unknown_type),
            (
                "Type=gamma,Alpha=2,Beta=2MB",
                ParseSizeError::is_removed_type,
            ),
            (
                "Type=normal,Mean=20MB,StdDev=1MB",
                ParseSizeError::is_removed_type,
            ),
            // Parameter names are validated at parse time.
            (
                "Type=lognormal,Median=1kb,Sigma=0,Max=2kb,Foo=2",
                ParseSizeError::is_unknown_parameter,
            ),
            (
                "Type=lognormal,Median=1kb,Sigma=0",
                ParseSizeError::is_missing_parameter,
            ),
            (
                "Type=pareto,Min=4KB,Max=1GB,Alpha=1.2MB",
                ParseSizeError::is_not_a_byte_size,
            ),
        ];
        for (input, matches) in cases {
            let err = parse_error(input);
            assert!(matches(&err), "{input}: {err}");
        }
    }

    #[test]
    fn removed_types_name_their_replacement() {
        assert_eq!(
            parse_error("Type=gamma,Alpha=2,Beta=2MB").to_string(),
            "Type gamma was removed; use Type=pareto,Min=<bytes>,Max=<bytes>,Alpha=<shape> \
             for a heavy tail"
        );
        assert_eq!(
            parse_error("Type=normal,Mean=20MB,StdDev=1MB").to_string(),
            "Type normal was removed; use a range such as 19MB-21MB, or \
             Type=lognormal,Median=<bytes>,Sigma=<number>,Max=<bytes> with Sigma set to \
             StdDev divided by Mean"
        );
        assert_eq!(
            parse_error("Type=zipf,Mean=1").to_string(),
            "unknown Type \"zipf\", must be one of: lognormal,pareto"
        );
    }

    #[test]
    fn unknown_parameters_list_the_accepted_keys() {
        // The old log-space lognormal grammar gets its translation.
        let err = parse_error("Type=lognormal,Mean=16,StdDev=1");
        assert!(err.is_unknown_parameter());
        assert_eq!(
            err.to_string(),
            "unknown parameter \"Mean\" for Type=lognormal; lognormal takes \
             Median=<bytes>,Sigma=<number>,Max=<bytes> (Median=8.5MB matches the old Mean=16)"
        );
        assert_eq!(
            parse_error("Type=lognormal,Median=1kb,Sigma=0,Max=2kb,Foo=2").to_string(),
            "unknown parameter \"Foo\" for Type=lognormal; lognormal takes Median, Sigma, Min, Max"
        );
        assert_eq!(
            parse_error("Type=pareto,Min=4KB,Max=1GB,Alpha=1.2,Beta=1").to_string(),
            "unknown parameter \"Beta\" for Type=pareto; pareto takes Min, Max, Alpha"
        );
    }

    #[test]
    fn max_is_required_for_both_distributions() {
        let err = parse_error("Type=pareto,Min=4KB,Alpha=1.2");
        assert!(err.is_missing_parameter());
        assert_eq!(err.to_string(), "missing parameter Max for Type=pareto");
        let err = parse_error("Type=lognormal,Median=1MB,Sigma=1");
        assert!(err.is_missing_parameter());
        assert_eq!(err.to_string(), "missing parameter Max for Type=lognormal");
    }

    #[test]
    fn dimensionless_keys_reject_suffixes_and_non_numbers() {
        let err = parse_error("Type=pareto,Min=4KB,Max=1GB,Alpha=1.2MB");
        assert!(err.is_not_a_byte_size());
        assert_eq!(err.to_string(), "Alpha is a plain number, not a byte size");
        let err = parse_error("Type=lognormal,Median=1MB,Sigma=1kb,Max=1GB");
        assert!(err.is_not_a_byte_size());
        assert_eq!(err.to_string(), "Sigma is a plain number, not a byte size");

        for input in [
            "Type=pareto,Min=4KB,Max=1GB,Alpha=abc",
            "Type=pareto,Min=4KB,Max=1GB,Alpha=inf",
            "Type=lognormal,Median=1MB,Sigma=nan,Max=1GB",
            "Type=lognormal,Median=1MB,Sigma=,Max=1GB",
        ] {
            let err = parse_error(input);
            assert!(err.is_invalid_number(), "{input}: {err}");
        }
        assert_eq!(
            parse_error("Type=pareto,Min=4KB,Max=1GB,Alpha=abc").to_string(),
            "invalid Alpha value \"abc\": not a finite number"
        );
    }

    #[test]
    fn parameters_are_validated_in_both_constructors() {
        let err = parse_error("Type=pareto,Min=4KB,Max=1GB,Alpha=0");
        assert!(
            err.invalid_spec_error()
                .is_some_and(SizeSpecError::is_invalid_distribution)
        );
        assert_eq!(err.to_string(), "Alpha must be greater than zero");
        assert!(
            SizeSpec::pareto(-1.0, 4096..=8192)
                .unwrap_err()
                .is_invalid_distribution()
        );
        assert!(
            SizeSpec::pareto(f64::NAN, 4096..=8192)
                .unwrap_err()
                .is_invalid_distribution()
        );
        assert!(
            SizeSpec::pareto(f64::INFINITY, 4096..=8192)
                .unwrap_err()
                .is_invalid_distribution()
        );

        let err = parse_error("Type=lognormal,Median=0,Sigma=1,Max=1GB");
        assert_eq!(err.to_string(), "Median must be at least 1");
        let err = parse_error("Type=lognormal,Median=1MB,Sigma=-1,Max=1GB");
        assert_eq!(err.to_string(), "Sigma must be at least zero");
        assert!(
            SizeSpec::lognormal(1024, f64::NAN, 60..=2048)
                .unwrap_err()
                .is_invalid_distribution()
        );
        assert!(
            SizeSpec::lognormal(1024, f64::INFINITY, 60..=2048)
                .unwrap_err()
                .is_invalid_distribution()
        );
    }

    #[test]
    #[expect(
        clippy::reversed_empty_ranges,
        reason = "the inverted band is what this rejection test builds"
    )]
    fn bands_are_validated_in_both_constructors() {
        let err = parse_error("Type=lognormal,Median=1MB,Sigma=0,Min=1MB,Max=1MB");
        assert!(
            err.invalid_spec_error()
                .is_some_and(SizeSpecError::is_empty_band)
        );
        assert_eq!(
            err.to_string(),
            "size band 1048576..=1048576 holds one size; use --file-size 1MB instead"
        );
        assert_eq!(
            parse_error("Type=pareto,Min=4097,Max=4097,Alpha=1").to_string(),
            "size band 4097..=4097 holds one size; use --file-size 4097 instead"
        );
        let err = SizeSpec::pareto(1.0, 8192..=4096).unwrap_err();
        assert!(err.is_empty_band());
        assert_eq!(
            err.to_string(),
            "size band 8192..=4096 is empty: Min exceeds Max"
        );

        let err = parse_error("Type=lognormal,Median=1MB,Sigma=1,Min=10,Max=1GB");
        assert!(
            err.invalid_spec_error()
                .is_some_and(SizeSpecError::is_band_too_low)
        );
        assert_eq!(
            err.to_string(),
            "Min must be at least 60 bytes, the header size"
        );
        assert!(
            SizeSpec::pareto(1.0, 59..=4096)
                .unwrap_err()
                .is_band_too_low()
        );
        assert!(
            SizeSpec::lognormal(1024, 1.0, 0..=4096)
                .unwrap_err()
                .is_band_too_low()
        );

        // The lowest allowed band edge is the header itself, and the
        // median may sit outside the band.
        assert_eq!(
            SizeSpec::pareto(1.0, 60..=61).unwrap().to_string(),
            "Type=pareto,Min=60,Max=61,Alpha=1"
        );
        assert_eq!(
            SizeSpec::lognormal(1 << 40, 1.0, 60..=61)
                .unwrap()
                .to_string(),
            "Type=lognormal,Median=1099511627776,Sigma=1,Min=60,Max=61"
        );
    }

    #[test]
    fn canonical_display_round_trips_through_parse() {
        for (input, canonical) in [
            ("4096", "4096"),
            ("2kb", "2048"),
            ("1kb-2kb", "1024-2048"),
            (
                "Type=lognormal,Median=20MB,Sigma=0.05,Max=10MB",
                "Type=lognormal,Median=20971520,Sigma=0.05,Min=60,Max=10485760",
            ),
            (
                "Type=lognormal,Median=1MB,Sigma=1.5,Min=4KB,Max=1GB",
                "Type=lognormal,Median=1048576,Sigma=1.5,Min=4096,Max=1073741824",
            ),
            (
                "Type=lognormal,Median=1MB,Sigma=2,Max=1GB",
                "Type=lognormal,Median=1048576,Sigma=2,Min=60,Max=1073741824",
            ),
            (
                "Type=pareto,Min=4KB,Max=1GB,Alpha=1.2",
                "Type=pareto,Min=4096,Max=1073741824,Alpha=1.2",
            ),
            (
                "Type=pareto,Max=1GB,Min=4KB,Alpha=2",
                "Type=pareto,Min=4096,Max=1073741824,Alpha=2",
            ),
        ] {
            let parsed = spec(input);
            assert_eq!(parsed.to_string(), canonical, "{input}");
            assert_eq!(spec(canonical), parsed, "{canonical}");
        }
    }

    #[test]
    fn shorthand_item_without_equals_is_an_error() {
        let err = parse_error("Type=lognormal,Median");
        assert!(err.is_malformed_parameter());
        let err = parse_error("Type=lognormal,Median=1=2");
        assert!(err.is_malformed_parameter());
    }

    #[test]
    fn shorthand_duplicate_parameter_keeps_the_last_value() {
        // A repeated key silently overwrites its previous value.
        assert_eq!(
            spec("Type=lognormal,Median=1,Median=1kb,Sigma=0,Max=2kb"),
            SizeSpec::lognormal(1024, 0.0, 60..=2048).unwrap()
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
        let err = parse_error("2kb-1kb");
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
    fn lognormal_with_zero_sigma_is_exactly_the_median() {
        // Median is a byte size, so Sigma=0 gives exactly 1024 bytes.
        assert_eq!(one_size("Type=lognormal,Median=1kb,Sigma=0,Max=2kb"), 1024);
        // The sampler scales the median directly rather than computing
        // e^ln(median), which lands one bit low for 1GB and would
        // truncate to 1073741823.
        assert_eq!(
            one_size("Type=lognormal,Median=1GB,Sigma=0,Max=2GB"),
            1 << 30
        );
        assert_eq!(
            one_size("Type=lognormal,Median=1TB,Sigma=0,Max=2TB"),
            1 << 40
        );
    }

    #[test]
    fn pareto_samples_start_at_min_and_stay_below_max() {
        let mut sizes = spec("Type=pareto,Min=4KB,Max=8KB,Alpha=1")
            .chooser()
            .unwrap();
        for _ in 0..256 {
            let size = sizes.next_size().unwrap();
            assert!((4096..=8192).contains(&size), "{size}");
        }
    }

    #[test]
    fn pareto_min_defaults_to_the_header_size() {
        assert_eq!(
            spec("Type=pareto,Max=4KB,Alpha=1.2"),
            SizeSpec::pareto(1.2, 60..=4096).unwrap()
        );
    }

    #[test]
    fn low_mass_bands_never_return_a_size() {
        for input in [
            "Type=lognormal,Median=3KB,Sigma=1,Max=100",
            "Type=lognormal,Median=3KB,Sigma=0,Max=100",
            "Type=pareto,Min=60,Max=61,Alpha=0.001",
        ] {
            let mut sizes = spec(input).chooser().unwrap();
            for _ in 0..100 {
                let error = sizes
                    .next_size()
                    .expect_err("reject before returning any size");
                assert_eq!(error.spec(), &spec(input));
            }
        }
    }

    #[test]
    fn supported_tail_and_narrow_bands_keep_sampling() {
        for input in [
            "Type=lognormal,Median=3KB,Sigma=1,Max=400",
            "Type=lognormal,Median=3KB,Sigma=1,Min=3000,Max=3100",
            "Type=pareto,Min=60,Max=61,Alpha=1",
        ] {
            let mut sizes = spec(input).chooser().unwrap();
            for _ in 0..1000 {
                sizes.next_size().expect("supported band keeps sampling");
            }
        }
    }

    #[test]
    fn unsupported_band_is_a_reported_error() {
        // The band holds 6e-44 of the mass, so the first file fails.
        let parsed = spec("Type=lognormal,Median=20MB,Sigma=0.05,Max=10MB");
        let mut sizes = parsed.chooser().unwrap();
        let err = sizes.next_size().unwrap_err();
        assert_eq!(
            err.to_string(),
            "insufficient probability mass within 60..=10485760 bytes for \
             Type=lognormal,Median=20971520,Sigma=0.05,Min=60,Max=10485760"
        );
        assert_eq!(err.spec(), &parsed);
        assert_eq!(err.band(), 60..=10_485_760);
        assert_eq!(
            format!("{sizes:?}"),
            "SizeChooser::Sampled(Type=lognormal,Median=20971520,Sigma=0.05,Min=60,Max=10485760)"
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

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        /// With the median inside the band, the band holds at least an
        /// eighth of the mass, so 1,000 draws never exhaust it and every
        /// one lands inside it.
        #[test]
        fn lognormal_samples_stay_inside_the_band(
            min in 60_u64..=(1 << 30),
            factor in 2_u64..=1024,
            median_factor in 1_u64..=1024,
            sigma in 0.0_f64..=2.0,
        ) {
            let max = min * factor;
            let median = min * median_factor.min(factor);
            let mut sizes = SizeSpec::lognormal(median, sigma, min..=max)
                .expect("the parameters are valid")
                .chooser()
                .expect("the random source works");
            for _ in 0..1000 {
                let size = sizes.next_size().expect("the band holds enough mass");
                prop_assert!((min..=max).contains(&size), "{size} outside {min}..={max}");
            }
        }

        /// A band spanning at least a factor of two holds at least
        /// `1 - 2^-alpha` of a Pareto's mass, so no draw is ever
        /// rejected often enough to fail.
        #[test]
        fn pareto_samples_stay_inside_the_band(
            min in 60_u64..=(1 << 30),
            factor in 2_u64..=1024,
            alpha in 0.1_f64..=5.0,
        ) {
            let max = min * factor;
            let mut sizes = SizeSpec::pareto(alpha, min..=max)
                .expect("the parameters are valid")
                .chooser()
                .expect("the random source works");
            for _ in 0..1000 {
                let size = sizes.next_size().expect("the band holds enough mass");
                prop_assert!((min..=max).contains(&size), "{size} outside {min}..={max}");
            }
        }
    }
}
