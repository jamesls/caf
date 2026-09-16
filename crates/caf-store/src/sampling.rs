//! Frozen CAF v3 generation sampling algorithms.
//!
//! Operation order and draw consumption are part of `docs/generation.md`.
//! Exact-output tests in `size` and this module pin the implementations.

use rand_chacha::rand_core::RngCore;

// These exact binary fractions convert the top 53 random bits to the
// CAF v3 intervals. Changing either changes every distribution sample.
const TWO_NEG_52: f64 = 1.0 / 4_503_599_627_370_496.0;
const TWO_NEG_53: f64 = 1.0 / 9_007_199_254_740_992.0;

/// Frozen conversion to [-1, 1); pinned by `unit_interval_endpoints`.
#[expect(
    clippy::cast_precision_loss,
    reason = "the top 53 bits fit exactly in f64"
)]
fn signed_unit(word: u64) -> f64 {
    (word >> 11) as f64 * TWO_NEG_52 - 1.0
}

/// Frozen conversion to (0, 1]; pinned by `unit_interval_endpoints`.
#[expect(
    clippy::cast_precision_loss,
    reason = "integers through 2^53 fit exactly in f64"
)]
fn open_closed_unit(word: u64) -> f64 {
    ((word >> 11) + 1) as f64 * TWO_NEG_53
}

/// Frozen inclusive uniform sampler; rejection and boundaries have exact-output tests.
pub(crate) fn uniform(rng: &mut impl RngCore, start: u64, end: u64) -> u64 {
    if start == end {
        return start;
    }
    if start == 0 && end == u64::MAX {
        return rng.next_u64();
    }
    let outcomes = end - start + 1;
    let reject_below = outcomes.wrapping_neg() % outcomes;
    loop {
        let word = rng.next_u64();
        if word >= reject_below {
            return start + word % outcomes;
        }
    }
}

/// Frozen polar sampler; both rejection paths have exact-output tests.
pub(crate) fn normal(rng: &mut impl RngCore) -> f64 {
    loop {
        let first = signed_unit(rng.next_u64());
        let second = signed_unit(rng.next_u64());
        let squared = first * first + second * second;
        if squared == 0.0 || squared >= 1.0 {
            continue;
        }
        let logarithm = libm::log(squared);
        let multiplier = libm::sqrt((-2.0 * logarithm) / squared);
        // Deliberately discard the second normal sample in CAF v3 generation.
        return first * multiplier;
    }
}

/// Frozen Pareto transform; pinned by the seeded size sequence tests in `size`.
pub(crate) fn pareto(rng: &mut impl RngCore, min: f64, inv_neg_alpha: f64) -> f64 {
    min * libm::pow(open_closed_unit(rng.next_u64()), inv_neg_alpha)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{RngCore, normal, open_closed_unit, signed_unit, uniform};

    /// Scripted 64-bit draws; unexpected draws fail the test immediately.
    pub(crate) struct Words(pub(crate) std::vec::IntoIter<u64>);

    impl RngCore for Words {
        fn next_u64(&mut self) -> u64 {
            self.0.next().expect("no extra draws are permitted")
        }

        fn next_u32(&mut self) -> u32 {
            panic!("CAF v3 generation only draws u64 values")
        }

        fn fill_bytes(&mut self, _: &mut [u8]) {
            panic!("CAF v3 generation only draws u64 values")
        }
    }

    #[test]
    fn unit_interval_endpoints() {
        assert_eq!(signed_unit(0).to_bits(), (-1.0_f64).to_bits());
        assert_eq!(signed_unit(1 << 63).to_bits(), 0.0_f64.to_bits());
        assert_eq!(
            signed_unit(u64::MAX).to_bits(),
            (1.0 - super::TWO_NEG_52).to_bits()
        );
        assert_eq!(open_closed_unit(0).to_bits(), super::TWO_NEG_53.to_bits());
        assert_eq!(open_closed_unit(u64::MAX).to_bits(), 1.0_f64.to_bits());
        assert_eq!(signed_unit(2047).to_bits(), signed_unit(0).to_bits());
        assert_eq!(
            open_closed_unit(2047).to_bits(),
            open_closed_unit(0).to_bits()
        );
    }

    #[test]
    fn uniform_rejection_and_integer_boundaries() {
        let mut words = Words(vec![0, 5, 6, u64::MAX, 0, u64::MAX].into_iter());
        assert_eq!(uniform(&mut words, 100, 109), 106);
        assert_eq!(uniform(&mut words, 0, u64::MAX), u64::MAX);
        assert_eq!(uniform(&mut words, 0, u64::MAX), 0);
        assert_eq!(uniform(&mut words, u64::MAX - 1, u64::MAX), u64::MAX);
        assert_eq!(uniform(&mut words, u64::MAX, u64::MAX), u64::MAX);
        assert_eq!(uniform(&mut words, 0, 0), 0);
        assert_eq!(words.0.next(), None);
    }

    #[test]
    fn polar_rejects_zero_boundary_and_outside_circle_without_caching() {
        let zero = 1 << 63;
        let half = 3 << 62;
        let mut words = Words(vec![zero, zero, 0, zero, 0, 0, half, zero, half, zero].into_iter());
        // V1=0.5, V2=0 gives sqrt(-2 ln(1/4)); the second sample is discarded.
        let expected = 1.665_109_222_315_395_4_f64.to_bits();
        assert_eq!(normal(&mut words).to_bits(), expected);
        assert_eq!(normal(&mut words).to_bits(), expected);
        assert_eq!(words.0.next(), None);
    }
}
