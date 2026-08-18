//! Deterministic SHAKE-128 content generation.
//!
//! File content is derived from the header's content seed so verifiers can
//! regenerate expected bytes without external data. Each block is the
//! SHAKE-128 output over `CONTENT_DOMAIN || seed || block_index` (8-byte
//! big-endian index), squeezed to the full block length; the SHAKE
//! instance never spans blocks. Block 0 is shortened by the header size so
//! later blocks start at 1 MiB-aligned file offsets.

use std::fmt::{self, Debug, Formatter};
use std::io::{self, Read};

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake128, Shake128Reader};

use crate::seed::ContentSeed;
use crate::{BLOCK_SIZE, CONTENT_DOMAIN, HEADER_SIZE};

/// Returns the content length in bytes of the block at `index`.
///
/// Block 0 is [`BLOCK_SIZE`] − [`HEADER_SIZE`] bytes; every later block is
/// [`BLOCK_SIZE`] bytes.
#[must_use]
pub fn block_len(index: u64) -> usize {
    if index == 0 {
        BLOCK_SIZE - HEADER_SIZE
    } else {
        BLOCK_SIZE
    }
}

/// Fills `block` with the complete content block at `index`.
///
/// Blocks are independently derivable, so callers can generate them in any
/// order (or in parallel) and reuse one buffer per block size. For
/// sequential streaming use [`ContentReader`].
///
/// # Panics
///
/// Panics if `block.len()` is not exactly [`block_len`]`(index)`: a
/// partial block would not be the version 2 content stream.
pub fn fill_block(seed: ContentSeed, index: u64, block: &mut [u8]) {
    assert_eq!(
        block.len(),
        block_len(index),
        "content block {index} is {} bytes",
        block_len(index),
    );
    XofReader::read(&mut block_reader(seed, index), block);
}

/// Starts the SHAKE-128 XOF for one content block.
///
/// SHAKE output is prefix-stable: squeezing a block incrementally yields
/// the same bytes as squeezing it at full length, so readers may consume
/// only the prefix a short file needs.
fn block_reader(seed: ContentSeed, index: u64) -> Shake128Reader {
    let mut shake = Shake128::default();
    shake.update(CONTENT_DOMAIN);
    shake.update(seed.as_bytes());
    shake.update(&index.to_be_bytes());
    shake.finalize_xof()
}

/// An infinite deterministic content stream for one seed.
///
/// Yields the concatenation of all content blocks for the seed. The bytes
/// read are independent of the read chunk sizes. The stream never ends and
/// never fails; bound it with [`Read::take`] to a file's content length.
///
/// # Examples
///
/// ```
/// use std::io::Read;
///
/// use caf_format::{ContentReader, ContentSeed};
///
/// let seed = ContentSeed::from_hex("b42d9a6630882f79c7599ae213435f86")?;
/// let mut content = vec![0_u8; 4096 - 60];
/// ContentReader::new(seed).read_exact(&mut content)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct ContentReader {
    seed: ContentSeed,
    next_block_index: u64,
    /// XOF for the block currently being squeezed, if any.
    block: Option<Shake128Reader>,
    /// Bytes of the current block not yet squeezed.
    remaining_in_block: usize,
}

impl ContentReader {
    /// Creates a stream positioned at the first content byte.
    #[must_use]
    pub fn new(seed: ContentSeed) -> Self {
        Self {
            seed,
            next_block_index: 0,
            block: None,
            remaining_in_block: 0,
        }
    }

    /// Returns the seed this stream derives content from.
    #[must_use]
    pub fn seed(&self) -> ContentSeed {
        self.seed
    }

    /// Fills `buf` with the next bytes of the stream.
    ///
    /// The stream is infinite and never fails, so `buf` is always filled
    /// completely; [`Read::read`] forwards here.
    pub fn fill(&mut self, buf: &mut [u8]) {
        let mut filled = 0;
        while filled < buf.len() {
            let wanted = buf.len() - filled;
            let (reader, remaining) = self.current_block();
            let take = wanted.min(remaining);
            XofReader::read(reader, &mut buf[filled..filled + take]);
            self.remaining_in_block -= take;
            filled += take;
        }
    }

    /// Returns the XOF bytes are next squeezed from and how many of them
    /// the current block still has, starting the next block's XOF when
    /// the current one is exhausted.
    fn current_block(&mut self) -> (&mut Shake128Reader, usize) {
        if self.remaining_in_block == 0 {
            let index = self.next_block_index;
            self.block = Some(block_reader(self.seed, index));
            self.remaining_in_block = block_len(index);
            self.next_block_index += 1;
        }
        let remaining = self.remaining_in_block;
        let reader = self
            .block
            .as_mut()
            .expect("a block reader exists while bytes remain");
        (reader, remaining)
    }
}

impl Read for ContentReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.fill(buf);
        Ok(buf.len())
    }
}

impl Debug for ContentReader {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContentReader")
            .field("seed", &self.seed)
            .field("next_block_index", &self.next_block_index)
            .field("remaining_in_block", &self.remaining_in_block)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::{ContentReader, block_len, fill_block};
    use crate::{BLOCK_SIZE, ContentSeed, HEADER_SIZE};

    fn seed() -> ContentSeed {
        ContentSeed::from_bytes(*b"0123456789abcdef")
    }

    #[test]
    fn block_lengths_match_the_specification() {
        assert_eq!(block_len(0), BLOCK_SIZE - HEADER_SIZE);
        assert_eq!(block_len(1), BLOCK_SIZE);
        assert_eq!(block_len(u64::MAX), BLOCK_SIZE);
    }

    #[test]
    #[should_panic(expected = "content block 0 is 1048516 bytes")]
    fn fill_block_rejects_partial_blocks() {
        fill_block(seed(), 0, &mut [0_u8; 16]);
    }

    #[test]
    fn reader_streams_the_blocks_fill_block_generates() {
        let mut reference = vec![0_u8; block_len(0) + block_len(1)];
        let (first, second) = reference.split_at_mut(block_len(0));
        fill_block(seed(), 0, first);
        fill_block(seed(), 1, second);

        let mut streamed = vec![0_u8; reference.len()];
        ContentReader::new(seed())
            .read_exact(&mut streamed)
            .unwrap();
        assert_eq!(streamed, reference);
    }

    #[test]
    fn reads_are_invariant_under_chunk_size() {
        let len = block_len(0) + 17;
        let mut one_shot = vec![0_u8; len];
        ContentReader::new(seed())
            .read_exact(&mut one_shot)
            .unwrap();

        let mut chunked = Vec::with_capacity(len);
        let mut reader = ContentReader::new(seed());
        let mut chunk = vec![0_u8; 65_521]; // prime, never block aligned
        let mut remaining = len;
        while remaining > 0 {
            let take = remaining.min(chunk.len());
            reader.read_exact(&mut chunk[..take]).unwrap();
            chunked.extend_from_slice(&chunk[..take]);
            remaining -= take;
        }
        assert_eq!(chunked, one_shot);
    }

    #[test]
    fn take_bounds_the_infinite_stream() {
        let mut content = Vec::new();
        ContentReader::new(seed())
            .take(1024)
            .read_to_end(&mut content)
            .unwrap();
        assert_eq!(content.len(), 1024);
    }
}
