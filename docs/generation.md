# Seeded dataset generation

CAF v3 supports reproducible datasets through `caf gen --seed`. Given the same
seed and generation arguments, a successful run in a fresh directory produces
the same dataset on every supported platform and release. The guarantee covers
relative paths and every file's bytes, including `.metadata`, file sizes, and
parent links. It excludes filesystem timestamps, ownership, inode numbers, and
physical allocation.

```console
caf gen --seed blahblah --max-files 100 --file-size 4096 --format v3
```

The destination directory, worker counts, progress reporting, and temporary
filenames do not affect the dataset. Generation appends chains to existing
stores, so reproducing a nonempty store requires identical starting contents
and invocation history. The guarantee applies only to completed runs.

## Supported format and defaults

Seeded generation requires `--format v3`, which is the default. Combining
`--seed` with `--format v2` is a usage error (exit status 2). The CLI reports
it before creating any files or directories. The library also rejects a seeded
generator configured for v2 before it touches the filesystem. These rules are
part of CAF v3. There is no separate generation version.

| Setting | Default |
| --- | --- |
| File format | `v3` |
| File size | 4096 bytes |
| Stopping condition | 100 files when neither stopping option is supplied |
| Minimum file size | 60 bytes |
| Distribution `Min` | 60 bytes |

CAF v3 headers, content, and identities follow [the file format](file-format.md).

Without `--seed`, content seeds and the size generator use fresh
operating-system randomness. The sampling algorithms below apply to both
seeded and unseeded runs. `dev corrupt-file --seed` keeps its integer seed
and is outside this specification.

## Seed derivation

The seed is the UTF-8 encoding of the argument exactly as supplied, with no
trimming, case folding, or Unicode normalization. Invalid UTF-8 and the empty
string are usage errors (exit status 2). Whitespace-only seeds are valid.

All derivation uses BLAKE3 `derive_key` with these exact context strings:

```text
master          = derive_key("caf:gen:seed:v3:master", seed_text_bytes)
size_rng_seed   = derive_key("caf:gen:seed:v3:size-rng", master)
content_seed(i) = derive_key("caf:gen:seed:v3:content-seed", master || LE64(i))[0:16]
```

Every `derive_key` result is 32 bytes. The content-seed key material is the
32-byte master followed by the eight-byte little-endian file index, 40 bytes
in total. The first file has index zero, and each completed file increments
the index. The content seed is the first 16 bytes of the result.

Size rejection cannot shift content seeds because sizes and content seeds use
separate derivation domains. Worker scheduling cannot affect the file index.
Temporary names use independent operating-system randomness through the
filesystem environment, including in seeded runs, so collisions and retries
cannot consume size draws or change content seeds. Temporary names do not
survive successful generation.

## Size random stream

The generator is `rand_chacha::ChaCha12Rng` version 0.9.0, initialized with
`SeedableRng::from_seed(size_rng_seed)`. Each draw is one `next_u64` call.
That pinned version defines how two 32-bit ChaCha words combine into one
64-bit word. Sampling never draws a platform-width integer.

One generator serves the entire run. CAF selects each file's size immediately
before writing that file. It consumes draws in file order and never
precomputes later sizes. Fixed sizes, single-value ranges, and lognormal
`Sigma=0` consume no draws.

## Bit-to-float conversions

For a 64-bit draw `x`, let `k = x >> 11`, the top 53 bits. Both conversions
below produce exactly representable IEEE-754 binary64 values:

| Name | Calculation | Interval |
| --- | --- | --- |
| Signed unit | `V = (k as f64) * 2^-52 - 1.0` | `[-1, 1)` |
| Open-closed unit | `U = ((k + 1) as f64) * 2^-53` | `(0, 1]` |

The open-closed conversion never returns zero. The signed conversion can
return zero and never returns positive one.

## Uniform integer sizes

To sample the inclusive `u64` range `[a, b]`:

1. If `a == b`, return `a` without drawing.
2. If `a == 0` and `b == u64::MAX`, return one raw draw.
3. Otherwise, let `n = b - a + 1`. Compute `r = n.wrapping_neg() % n`,
   which is `2^64 mod n`.
4. Draw `x`. If `x < r`, reject it and repeat this step.
5. Return `a + x % n`.

The accepted interval has a length divisible by `n`, so all outcomes have
equal probability. Power-of-two widths have `r = 0`. After sampling, the
generator clamps the selected size to at least 60 bytes, as it does for fixed
sizes.

## Lognormal sizes

When `Sigma=0`, return the integer `Median` without drawing, subject to the
band validation below. This preserves integers above `2^53`.

For positive `Sigma`, sample a standard normal with the Marsaglia polar
method in this exact operation order:

1. Draw two words and convert them to signed unit values `V1` and `V2`,
   in that order.
2. Compute `s = V1 * V1 + V2 * V2` without fused multiply-add.
3. If `s == 0` or `s >= 1`, discard both values and start again.
4. Compute `t = libm::log(s)`, then `m = libm::sqrt((-2.0 * t) / s)`.
5. Return `Z = V1 * m`. Discard the second normal sample and do not cache it.

Convert the median to binary64 and compute the candidate as
`median_f64 * libm::exp(sigma * Z)`. Then apply the truncation and band rules
below.

## Pareto sizes

Convert the band's lower edge to binary64 as `min_f64`. Compute
`inv_neg_alpha = -1.0 / alpha` once. For each candidate, draw one word,
convert it to an open-closed unit value `U`, and compute
`min_f64 * libm::pow(U, inv_neg_alpha)`.

## Mathematics and truncation

Size sampling calls `libm` version 0.2.16, pinned exactly, with the
`force-soft-floats` feature. All logarithms, exponentials, powers, square
roots, and `exp(x) - 1` operations call `libm::log`, `libm::exp`,
`libm::pow`, `libm::sqrt`, and `libm::expm1` explicitly. Neither
standard-library transcendental functions nor dependency feature selection
may substitute another backend.

Basic operations use IEEE-754 binary64 arithmetic in the order specified
here. Multiplication and addition are separate operations, never fused.
The pinned backend defines the expected results; the specification does not
require correctly rounded transcendental functions. A backend update must
preserve the expected seeded CAF v3 outputs.

For both sampled distributions:

1. Generate a candidate.
2. If it is not finite, reject it and redraw.
3. Truncate toward zero to a whole binary64 number.
4. Compare the truncated value with both inclusive band edges, converted
   to binary64. If it lies outside them, reject it and redraw.
5. Convert the accepted value to `u64` using Rust's saturating cast.

For example, `100.9` truncates to `100`, which `Max=100` accepts. Checking
the band before truncating would consume different draws. Truncation is
exact, and comparisons with integer edges are exact below `2^53` bytes.
Above that point the specified binary64 conversions still determine the
result. Zero-sigma lognormal sizes use the exact integer rule above.

## Band validation

Distributions require `Min >= 60` and `Max > Min`. The median must be a
positive integer. Sigma must be finite and nonnegative. Alpha must be finite
and positive. Before returning any size, the chooser checks that the
conservative acceptance mass is at least `0.005`. Unsupported bands report a
sampling error before CAF writes any data file or metadata.

For zero sigma, validation checks `Min <= Median <= Max` using exact `u64`
comparisons. This preserves band boundaries above `2^53`.

For positive sigma, compute:

```text
lower = libm::log(min_f64 / median_f64) / sigma
upper = libm::log((max_f64 + 1.0) / median_f64) / sigma
mass = 0.0
for index in 0..64:
    left = max(lower, -4.0 + f64(index) / 8.0)
    right = min(upper, -4.0 + f64(index + 1) / 8.0)
    if left < right:
        furthest = max(abs(left), abs(right))
        density = libm::exp((-0.5 * furthest) * furthest)
                  / libm::sqrt(2.0 * PI)
        mass = mass + (right - left) * density
```

`PI` is the binary64 constant `0x400921fb54442d18`. The 64 rectangles are
each one eighth of a standard deviation wide. They ignore tails beyond four
standard deviations and use the smallest density in each interval.

For Pareto, compute the mass as
`-libm::expm1(alpha * libm::log(min_f64 / (max_f64 + 1.0)))`.
Both calculations count fractions that truncate to `Max`. Once a band passes
validation, sampling retries without limit.

## Parsing and stopping

Seeded generation uses the size grammar in `caf-store/src/size.rs`. Plain
integers are bytes. Case-insensitive `kb`, `mb`, `gb`, and `tb` suffixes
multiply by powers of 1024. Decimal byte values require a suffix. The parser
multiplies them in binary64 and truncates toward zero. Integer byte values use
checked `u64` arithmetic. The parser rejects single-letter suffixes and
exponent notation in byte values.

The parser tries a size specification as a plain integer first, then as
distribution shorthand if it contains a comma, then as an inclusive
`START-END` range if it contains a hyphen, then as a suffixed or decimal
fixed size. Distribution keys and type names are case-sensitive. Repeated
parameters keep their last value. `Type=lognormal` requires `Median`,
`Sigma`, and `Max`. `Type=pareto` requires `Alpha` and `Max`. Both accept an
optional `Min` and reject unknown keys. Dimensionless parameters accept
finite binary64 numbers without byte suffixes.

The generator checks both stopping conditions before each file. The run stops
when the completed file count reaches `--max-files` or the byte count reaches
`--max-disk-usage`. The last file may overshoot the byte limit. Byte totals
use saturating `u64` addition. Negative CLI file counts behave as zero. When
the user gives neither limit, the CLI selects 100 files. When the user gives
one limit, the other is unbounded. A zero-file run still writes the zero
chain-tip marker and aggregate. Each run starts with a zero parent link.

## Conformance tests

[`tests/golden/generation-v3.json`](../tests/golden/generation-v3.json)
pins the master, size-generator seed, indexed content seeds, raw RNG words,
size sequences, chain tips, and aggregate digests. The recipes cover fixed,
range, lognormal, and Pareto sizes in CAF v3. Each recipe has three files of
at least 4 MiB so two workers exercise the parallel write path. Tests compare
every relative file path and byte between serial and parallel runs and verify
all content and parent links.

The release-gating matrix runs on Linux x86-64, Linux ARM64, and macOS:

```sh
cargo test --workspace --locked
cargo build --release --locked -p caf --bin caf
CAF_RELEASE_BIN="$PWD/target/release/caf" cargo test --locked -p caf --test seeded_generation
```

The final command runs the separately built production executable in fresh
directories against the same expected values as the library tests.
`cargo test --release` alone includes development dependencies and does not
replace this check. The pinned values must stay unchanged when
implementations, dependencies, or compilers change.
