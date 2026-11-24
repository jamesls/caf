//! Multi-way SHAKE-128 content generation for x86-64.
//!
//! Every content block is its own SHAKE-128 stream, so several blocks can
//! be squeezed in lockstep: lane `j` of every stream's Keccak state shares
//! one vector register, and each instruction advances all of them. AVX-512
//! runs 8 streams at once and AVX2 runs 4. The CPU is checked at run time,
//! so a generic x86-64 build uses the widest kernel the machine has; other
//! CPUs keep the scalar path in `content`.
//!
//! A block's whole SHAKE input (24-byte domain, 16-byte seed, 8-byte
//! index) fits in one 168-byte rate block, so absorbing is a single padded
//! block. The squeezed bytes equal the scalar path's byte for byte.
//!
//! This is the workspace's one exception to its `unsafe` ban: calling a
//! `#[target_feature]` kernel after the runtime check that makes it sound,
//! and storing vector registers to arrays.
#![allow(
    unsafe_code,
    reason = "runtime-dispatched AVX2 and AVX-512 kernels; see the module docs"
)]

use crate::Format;
use crate::seed::ContentSeed;
#[cfg(target_arch = "x86_64")]
use crate::{CONTENT_DOMAIN_V2, CONTENT_DOMAIN_V3};

/// Most blocks any kernel generates together.
pub(crate) const MAX_WAYS: usize = 8;

/// SHAKE-128 rate in bytes and in 64-bit lanes.
#[cfg(target_arch = "x86_64")]
const RATE: usize = 168;
#[cfg(target_arch = "x86_64")]
const RATE_LANES: usize = RATE / 8;

/// Keccak-f\[1600\] round constants.
#[cfg(target_arch = "x86_64")]
const RC: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// Blocks the fastest kernel on this CPU generates together: 8 with
/// AVX-512, 4 with AVX2, otherwise 1.
#[cfg(target_arch = "x86_64")]
pub(crate) fn ways() -> usize {
    if std::arch::is_x86_feature_detected!("avx512f") {
        8
    } else if std::arch::is_x86_feature_detected!("avx2") {
        4
    } else {
        1
    }
}

/// Blocks generated together on this architecture: always 1.
#[cfg(not(target_arch = "x86_64"))]
pub(crate) fn ways() -> usize {
    1
}

/// Fills `prefixes`, the leading bytes of consecutive content blocks from
/// `first_index`, with a multi-way kernel. Returns `false` without writing
/// when no kernel fits this batch on this CPU.
///
/// The caller has checked every prefix against its block length.
#[cfg(target_arch = "x86_64")]
pub(crate) fn fill(
    format: Format,
    seed: ContentSeed,
    first_index: u64,
    prefixes: &mut [&mut [u8]],
) -> bool {
    let count = prefixes.len();
    if (5..=8).contains(&count) && std::arch::is_x86_feature_detected!("avx512f") {
        // SAFETY: the check above proved this CPU supports AVX-512F, the
        // only target feature `avx512::fill` enables.
        unsafe { avx512::fill(format, seed, first_index, prefixes) };
        true
    } else if (2..=4).contains(&count) && std::arch::is_x86_feature_detected!("avx2") {
        // SAFETY: the check above proved this CPU supports AVX2, the only
        // target feature `avx2::fill` enables.
        unsafe { avx2::fill(format, seed, first_index, prefixes) };
        true
    } else {
        false
    }
}

/// No multi-way kernel exists for this architecture.
#[cfg(not(target_arch = "x86_64"))]
pub(crate) fn fill(_: Format, _: ContentSeed, _: u64, _: &mut [&mut [u8]]) -> bool {
    false
}

/// The one padded SHAKE-128 rate block holding a content block's input,
/// as little-endian lanes.
#[cfg(target_arch = "x86_64")]
fn padded_block(format: Format, seed: ContentSeed, index: u64) -> [u64; RATE_LANES] {
    let domain = match format {
        Format::V2 => CONTENT_DOMAIN_V2,
        Format::V3 => CONTENT_DOMAIN_V3,
    };
    let mut block = [0_u8; RATE];
    let mut len = 0;
    for part in [domain, seed.as_bytes().as_slice(), &index.to_be_bytes()] {
        block[len..len + part.len()].copy_from_slice(part);
        len += part.len();
    }
    // SHAKE domain bits and the first pad bit, then the last pad bit.
    block[len] ^= 0x1f;
    block[RATE - 1] ^= 0x80;
    std::array::from_fn(|lane| {
        let bytes = block[8 * lane..8 * lane + 8]
            .try_into()
            .expect("a lane is eight bytes");
        u64::from_le_bytes(bytes)
    })
}

/// Defines `keccak_f1600` and `fill` for one vector width from the
/// invoking module's `V`, `WAYS`, and lane helpers.
#[cfg(target_arch = "x86_64")]
macro_rules! multi_way_sponge {
    ($feature:literal) => {
        /// Keccak-f\[1600\] on `WAYS` states in lockstep.
        #[target_feature(enable = $feature)]
        #[allow(
            clippy::needless_range_loop,
            clippy::many_single_char_names,
            reason = "the Keccak steps are defined by lane coordinates"
        )]
        fn keccak_f1600(a: &mut [V; 25]) {
            for rc in super::RC {
                // θ
                let mut c = [a[0]; 5];
                for x in 0..5 {
                    c[x] = xor3(xor3(a[x], a[x + 5], a[x + 10]), a[x + 15], a[x + 20]);
                }
                for x in 0..5 {
                    let d = xor(c[(x + 4) % 5], rol::<1, 63>(c[(x + 1) % 5]));
                    for y in 0..5 {
                        a[x + 5 * y] = xor(a[x + 5 * y], d);
                    }
                }
                // ρ and π: lane x + 5y moves to y + 5(2x + 3y), rotated.
                let b = [
                    a[0],
                    rol::<44, 20>(a[6]),
                    rol::<43, 21>(a[12]),
                    rol::<21, 43>(a[18]),
                    rol::<14, 50>(a[24]),
                    rol::<28, 36>(a[3]),
                    rol::<20, 44>(a[9]),
                    rol::<3, 61>(a[10]),
                    rol::<45, 19>(a[16]),
                    rol::<61, 3>(a[22]),
                    rol::<1, 63>(a[1]),
                    rol::<6, 58>(a[7]),
                    rol::<25, 39>(a[13]),
                    rol::<8, 56>(a[19]),
                    rol::<18, 46>(a[20]),
                    rol::<27, 37>(a[4]),
                    rol::<36, 28>(a[5]),
                    rol::<10, 54>(a[11]),
                    rol::<15, 49>(a[17]),
                    rol::<56, 8>(a[23]),
                    rol::<62, 2>(a[2]),
                    rol::<55, 9>(a[8]),
                    rol::<39, 25>(a[14]),
                    rol::<41, 23>(a[15]),
                    rol::<2, 62>(a[21]),
                ];
                // χ
                for y in 0..5 {
                    for x in 0..5 {
                        a[x + 5 * y] =
                            chi(b[x + 5 * y], b[(x + 1) % 5 + 5 * y], b[(x + 2) % 5 + 5 * y]);
                    }
                }
                // ι
                a[0] = xor(a[0], splat(rc));
            }
        }

        /// Fills up to `WAYS` consecutive block prefixes in lockstep.
        /// Streams past the batch still run; their output is discarded.
        #[target_feature(enable = $feature)]
        pub(super) fn fill(
            format: super::Format,
            seed: super::ContentSeed,
            first_index: u64,
            prefixes: &mut [&mut [u8]],
        ) {
            debug_assert!(prefixes.len() <= WAYS);
            let absorbed: [[u64; super::RATE_LANES]; WAYS] = std::array::from_fn(|stream| {
                super::padded_block(format, seed, first_index.wrapping_add(stream as u64))
            });
            let mut state = [splat(0); 25];
            for (word, lane) in state.iter_mut().take(super::RATE_LANES).enumerate() {
                *lane = from_lanes(std::array::from_fn(|stream| absorbed[stream][word]));
            }

            let len = prefixes
                .iter()
                .map(|prefix| prefix.len())
                .max()
                .unwrap_or(0);
            let mut words = [[0_u64; WAYS]; super::RATE_LANES];
            let mut offset = 0;
            while offset < len {
                keccak_f1600(&mut state);
                for (out, lane) in words.iter_mut().zip(&state) {
                    *out = to_lanes(*lane);
                }
                for (stream, prefix) in prefixes.iter_mut().enumerate() {
                    let end = prefix.len().min(offset + super::RATE);
                    if offset >= end {
                        continue;
                    }
                    // Whole words as fixed 8-byte stores, then any tail.
                    let mut chunks = prefix[offset..end].chunks_exact_mut(8);
                    let mut word = words.iter();
                    for (bytes, lanes) in (&mut chunks).zip(&mut word) {
                        let bytes: &mut [u8; 8] =
                            bytes.try_into().expect("an exact chunk is eight bytes");
                        *bytes = lanes[stream].to_le_bytes();
                    }
                    let tail = chunks.into_remainder();
                    if let Some(lanes) = word.next() {
                        tail.copy_from_slice(&lanes[stream].to_le_bytes()[..tail.len()]);
                    }
                }
                offset += super::RATE;
            }
        }
    };
}

/// Four streams per `__m256i`, for CPUs with AVX2.
#[cfg(target_arch = "x86_64")]
mod avx2 {
    use std::arch::x86_64::{
        __m256i, _mm256_andnot_si256, _mm256_or_si256, _mm256_set_epi64x, _mm256_set1_epi64x,
        _mm256_slli_epi64, _mm256_srli_epi64, _mm256_storeu_si256, _mm256_xor_si256,
    };

    type V = __m256i;
    const WAYS: usize = 4;

    #[target_feature(enable = "avx2")]
    fn xor(a: V, b: V) -> V {
        _mm256_xor_si256(a, b)
    }

    #[target_feature(enable = "avx2")]
    fn xor3(a: V, b: V, c: V) -> V {
        _mm256_xor_si256(_mm256_xor_si256(a, b), c)
    }

    /// `a ^ (!b & c)`.
    #[target_feature(enable = "avx2")]
    fn chi(a: V, b: V, c: V) -> V {
        _mm256_xor_si256(a, _mm256_andnot_si256(b, c))
    }

    /// Rotates each lane left by `L`; `R` is `64 - L`. AVX2 has no rotate.
    #[target_feature(enable = "avx2")]
    fn rol<const L: i32, const R: i32>(x: V) -> V {
        _mm256_or_si256(_mm256_slli_epi64::<L>(x), _mm256_srli_epi64::<R>(x))
    }

    #[target_feature(enable = "avx2")]
    fn splat(word: u64) -> V {
        _mm256_set1_epi64x(word.cast_signed())
    }

    #[target_feature(enable = "avx2")]
    fn from_lanes(words: [u64; WAYS]) -> V {
        let [w0, w1, w2, w3] = words.map(u64::cast_signed);
        _mm256_set_epi64x(w3, w2, w1, w0)
    }

    #[target_feature(enable = "avx2")]
    fn to_lanes(x: V) -> [u64; WAYS] {
        let mut words = [0_u64; WAYS];
        // SAFETY: `words` is 32 writable bytes, and the unaligned store
        // has no alignment requirement.
        unsafe { _mm256_storeu_si256(words.as_mut_ptr().cast(), x) };
        words
    }

    multi_way_sponge!("avx2");
}

/// Eight streams per `__m512i`, for CPUs with AVX-512F. Its native rotate
/// and three-input logic each replace several AVX2 instructions.
#[cfg(target_arch = "x86_64")]
mod avx512 {
    use std::arch::x86_64::{
        __m512i, _mm512_rol_epi64, _mm512_set_epi64, _mm512_set1_epi64, _mm512_storeu_si512,
        _mm512_ternarylogic_epi64, _mm512_xor_si512,
    };

    type V = __m512i;
    const WAYS: usize = 8;

    #[target_feature(enable = "avx512f")]
    fn xor(a: V, b: V) -> V {
        _mm512_xor_si512(a, b)
    }

    /// `a ^ b ^ c` in one instruction (truth table 0x96).
    #[target_feature(enable = "avx512f")]
    fn xor3(a: V, b: V, c: V) -> V {
        _mm512_ternarylogic_epi64::<0x96>(a, b, c)
    }

    /// `a ^ (!b & c)` in one instruction (truth table 0xd2).
    #[target_feature(enable = "avx512f")]
    fn chi(a: V, b: V, c: V) -> V {
        _mm512_ternarylogic_epi64::<0xd2>(a, b, c)
    }

    /// Rotates each lane left by `L` with the native rotate; `R` is unused.
    #[target_feature(enable = "avx512f")]
    fn rol<const L: i32, const R: i32>(x: V) -> V {
        _mm512_rol_epi64::<L>(x)
    }

    #[target_feature(enable = "avx512f")]
    fn splat(word: u64) -> V {
        _mm512_set1_epi64(word.cast_signed())
    }

    #[target_feature(enable = "avx512f")]
    fn from_lanes(words: [u64; WAYS]) -> V {
        let [w0, w1, w2, w3, w4, w5, w6, w7] = words.map(u64::cast_signed);
        _mm512_set_epi64(w7, w6, w5, w4, w3, w2, w1, w0)
    }

    #[target_feature(enable = "avx512f")]
    fn to_lanes(x: V) -> [u64; WAYS] {
        let mut words = [0_u64; WAYS];
        // SAFETY: `words` is 64 writable bytes, and the unaligned store
        // has no alignment requirement.
        unsafe { _mm512_storeu_si512(words.as_mut_ptr().cast(), x) };
        words
    }

    multi_way_sponge!("avx512f");
}
