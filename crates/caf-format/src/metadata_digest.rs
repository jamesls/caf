//! Typed BLAKE2b-160 digests for the `.metadata/all` aggregate.

use std::fmt::{self, Debug, Display, Formatter};
use std::io::{self, Write};
use std::str::FromStr;

use crate::digest::Hasher;
use crate::hex::{self, ParseHexError};

/// A 20-byte BLAKE2b-160 digest of CAF metadata.
///
/// This type is deliberately distinct from the v2 [`Digest`](crate::Digest)
/// and v3 [`FileId`](crate::FileId) identity types. The on-disk hex shape is
/// the same, but a metadata aggregate must never be used as a file identity.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MetadataDigest([u8; Self::SIZE]);

impl MetadataDigest {
    /// Metadata digest length in bytes.
    pub const SIZE: usize = 20;

    /// Creates a metadata digest from its raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::SIZE]) -> Self {
        Self(bytes)
    }

    /// Computes the metadata digest of `data` in one shot.
    #[must_use]
    pub fn compute(data: impl AsRef<[u8]>) -> Self {
        let mut hasher = MetadataHasher::new();
        hasher.update(data);
        hasher.finalize()
    }

    /// Parses a metadata digest from 40 hex characters, accepting either case.
    ///
    /// # Errors
    ///
    /// Returns [`ParseHexError`] if the input is not exactly 40 hex
    /// characters.
    pub fn from_hex(value: impl AsRef<str>) -> Result<Self, ParseHexError> {
        hex::decode(value.as_ref()).map(Self)
    }

    /// Returns the raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::SIZE] {
        &self.0
    }

    /// Consumes the digest and returns its raw bytes.
    #[must_use]
    pub const fn into_inner(self) -> [u8; Self::SIZE] {
        self.0
    }

    /// Returns the 40-character lowercase hex form.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }
}

impl From<[u8; MetadataDigest::SIZE]> for MetadataDigest {
    fn from(bytes: [u8; MetadataDigest::SIZE]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl From<MetadataDigest> for [u8; MetadataDigest::SIZE] {
    fn from(digest: MetadataDigest) -> Self {
        digest.into_inner()
    }
}

impl AsRef<[u8]> for MetadataDigest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Display for MetadataDigest {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Debug for MetadataDigest {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "MetadataDigest({self})")
    }
}

impl FromStr for MetadataDigest {
    type Err = ParseHexError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::from_hex(value)
    }
}

/// Streaming BLAKE2b-160 hasher for the `.metadata/all` aggregate.
#[derive(Clone, Default)]
pub struct MetadataHasher(Hasher);

impl MetadataHasher {
    /// Creates a fresh metadata hasher.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds bytes to the metadata aggregate.
    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        self.0.update(data);
    }

    /// Finishes hashing and returns the typed metadata digest.
    #[must_use]
    pub fn finalize(self) -> MetadataDigest {
        MetadataDigest::from_bytes(self.0.finalize().into_inner())
    }
}

impl Debug for MetadataHasher {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("MetadataHasher").finish_non_exhaustive()
    }
}

impl Write for MetadataHasher {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::{MetadataDigest, MetadataHasher};

    #[test]
    fn one_shot_and_streaming_metadata_hashes_match() {
        let mut hasher = MetadataHasher::new();
        hasher.update(b"root-");
        hasher.write_all(b"names").unwrap();

        let digest = hasher.finalize();
        assert_eq!(digest, MetadataDigest::compute(b"root-names"));
        assert_eq!(digest.to_hex().parse::<MetadataDigest>().unwrap(), digest);
    }
}
