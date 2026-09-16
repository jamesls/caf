//! CAF v3 generation seed derivation, frozen by the vectors in this module's tests.

use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use caf_format::ContentSeed;

/// A text-derived seed for reproducible CAF v3 datasets.
///
/// Text is used as exact UTF-8 bytes, without trimming or normalization.
/// Size sampling and content derivation use separate BLAKE3 domains.
/// See `docs/generation.md` for the CAF v3 seeded generation contract.
///
/// # Examples
///
/// ```
/// use caf_store::GenerationSeed;
/// let seed = GenerationSeed::new("bug report 42")?;
/// assert_eq!(seed.content_seed(0), seed.content_seed(0));
/// # Ok::<(), caf_store::GenerationSeedError>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct GenerationSeed {
    master: [u8; 32],
}

impl GenerationSeed {
    /// Derives a generation seed from the exact bytes of `text`.
    ///
    /// # Examples
    ///
    /// ```
    /// let seed = caf_store::GenerationSeed::new("example")?;
    /// assert_ne!(seed.content_seed(0), seed.content_seed(1));
    /// # Ok::<(), caf_store::GenerationSeedError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`GenerationSeedError::Empty`] if `text` is empty.
    pub fn new(text: impl AsRef<str>) -> Result<Self, GenerationSeedError> {
        let text = text.as_ref();
        if text.is_empty() {
            return Err(GenerationSeedError::Empty);
        }
        Ok(Self {
            master: blake3::derive_key("caf:gen:seed:v3:master", text.as_bytes()),
        })
    }

    /// Returns the 32-byte seed for CAF v3's `ChaCha12` size generator.
    ///
    /// # Examples
    ///
    /// ```
    /// let seed = caf_store::GenerationSeed::new("example")?;
    /// assert_eq!(seed.size_rng_seed().len(), 32);
    /// # Ok::<(), caf_store::GenerationSeedError>(())
    /// ```
    #[must_use]
    pub fn size_rng_seed(&self) -> [u8; 32] {
        blake3::derive_key("caf:gen:seed:v3:size-rng", &self.master)
    }

    /// Returns the content seed for the zero-based file `index` in a run.
    ///
    /// This derivation is independent of sizes and worker scheduling.
    ///
    /// # Examples
    ///
    /// ```
    /// let seed = caf_store::GenerationSeed::new("example")?;
    /// assert_ne!(seed.content_seed(0), seed.content_seed(u64::MAX));
    /// # Ok::<(), caf_store::GenerationSeedError>(())
    /// ```
    #[must_use]
    pub fn content_seed(&self, index: u64) -> ContentSeed {
        // CAF v3 hashes the 32-byte master followed by LE64(index),
        // then takes the first 16 bytes required by the CAF header.
        let mut material = [0; 40];
        material[..32].copy_from_slice(&self.master);
        material[32..].copy_from_slice(&index.to_le_bytes());
        let derived = blake3::derive_key("caf:gen:seed:v3:content-seed", &material);
        let mut seed = [0; 16];
        seed.copy_from_slice(&derived[..16]);
        ContentSeed::from_bytes(seed)
    }
}

impl FromStr for GenerationSeed {
    type Err = GenerationSeedError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::new(text)
    }
}

/// Invalid text supplied as a generation seed.
///
/// # Examples
///
/// ```
/// use caf_store::{GenerationSeed, GenerationSeedError};
/// assert_eq!(GenerationSeed::new(""), Err(GenerationSeedError::Empty));
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum GenerationSeedError {
    /// The seed has no UTF-8 bytes.
    Empty,
}

impl Display for GenerationSeedError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("generation seed must not be empty"),
        }
    }
}

impl std::error::Error for GenerationSeedError {}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaCha12Rng;
    use rand_chacha::rand_core::{RngCore as _, SeedableRng as _};

    use super::{GenerationSeed, GenerationSeedError};

    #[test]
    fn seeded_v3_derivation_and_rng_vectors() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../../../tests/golden/generation-v3.json"))
                .expect("valid generation vectors");
        let seed = GenerationSeed::new(vectors["seed"].as_str().expect("seed text"))
            .expect("nonempty seed");
        assert_eq!(hex::encode(seed.master), vectors["master"]);
        assert_eq!(hex::encode(seed.size_rng_seed()), vectors["size_rng_seed"]);
        for content in vectors["content_seeds"]
            .as_array()
            .expect("content vectors")
        {
            assert_eq!(
                seed.content_seed(content["index"].as_u64().expect("index"))
                    .to_hex(),
                content["seed"]
            );
        }
        let mut rng = ChaCha12Rng::from_seed(seed.size_rng_seed());
        for word in vectors["words"].as_array().expect("raw words") {
            assert_eq!(rng.next_u64(), word.as_u64().expect("u64 word"));
        }
    }

    #[test]
    fn seed_text_is_exact_and_nonempty() {
        const fn assert_send_sync<T: Send + Sync>() {}

        assert_eq!(GenerationSeed::new(""), Err(GenerationSeedError::Empty));
        let texts = ["Seed", "seed", "seed ", " seed", " ", "é", "e\u{301}"];
        for (index, text) in texts.iter().enumerate() {
            let seed = GenerationSeed::new(text).expect("nonempty seed");
            assert_eq!(text.parse::<GenerationSeed>().expect("parse seed"), seed);
            for other in &texts[index + 1..] {
                assert_ne!(seed, GenerationSeed::new(other).expect("nonempty seed"));
            }
        }
        assert_send_sync::<GenerationSeed>();
        assert_send_sync::<GenerationSeedError>();
    }
}
