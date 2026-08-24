//! Deterministic SHAKE-128 content generation.
//!
//! File content is derived from the header's content seed so verifiers can
//! regenerate expected bytes without external data. Each block is the
//! SHAKE-128 output over `CONTENT_DOMAIN || seed || block_index` (8-byte
//! big-endian index), squeezed to the full block length; the SHAKE
//! instance never spans blocks. Block 0 is shortened by the header size so
//! later blocks start at 1 MiB-aligned file offsets. A file's last block
//! is squeezed only as far as the file length reaches
//! ([`fill_block_prefix`]), which SHAKE's prefix stability makes
//! equivalent to truncating the full block.

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
    fill_block_prefix(seed, index, block);
}

/// Fills `prefix` with the first `prefix.len()` bytes of the content
/// block at `index`.
///
/// The last block of a file is shorter than [`block_len`]`(index)`
/// whenever the file length is not block aligned; this is the entry
/// point that generates it. SHAKE output is prefix-stable, so the bytes
/// written are the ones [`ContentReader`] streams at the same file
/// offsets. Use [`fill_block`] when the block is known to be complete.
///
/// # Panics
///
/// Panics if `prefix` is longer than [`block_len`]`(index)`: bytes past
/// a block boundary belong to the next block's XOF, not this one's.
///
/// # Examples
///
/// ```
/// use caf_format::{ContentSeed, fill_block_prefix};
///
/// let seed = ContentSeed::from_hex("b42d9a6630882f79c7599ae213435f86")?;
/// let mut tail = [0_u8; 17];
/// fill_block_prefix(seed, 4, &mut tail);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn fill_block_prefix(seed: ContentSeed, index: u64, prefix: &mut [u8]) {
    assert!(
        prefix.len() <= block_len(index),
        "content block {index} is at most {} bytes",
        block_len(index),
    );
    XofReader::read(&mut block_reader(seed, index), prefix);
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

    /// Creates a content stream at the specified offset.
    ///
    /// The offset is content-relative: offset zero is the file byte at
    /// [`HEADER_SIZE`], not the start of the header. Every `u64` offset
    /// is supported without overflow. Locating it uses direct block
    /// arithmetic, then discards at most one block's prefix; it never
    /// advances through all preceding content.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::Read;
    ///
    /// use caf_format::{ContentReader, ContentSeed};
    ///
    /// let seed = ContentSeed::from_hex("b42d9a6630882f79c7599ae213435f86")?;
    /// let offset = 1_100_000_u64;
    /// let mut whole = vec![0_u8; offset as usize + 32];
    /// ContentReader::new(seed).read_exact(&mut whole)?;
    ///
    /// let mut from_offset = [0_u8; 32];
    /// ContentReader::new_with_offset(seed, offset).read_exact(&mut from_offset)?;
    /// assert_eq!(from_offset, whole[offset as usize..]);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn new_with_offset(seed: ContentSeed, offset: u64) -> Self {
        let first_len = block_len(0) as u64;
        let (block_index, mut offset_in_block) = if offset < first_len {
            (0, offset)
        } else {
            let after_first = offset - first_len;
            (
                1 + after_first / BLOCK_SIZE as u64,
                after_first % BLOCK_SIZE as u64,
            )
        };

        let mut reader = Self {
            seed,
            next_block_index: block_index,
            block: None,
            remaining_in_block: 0,
        };
        if offset_in_block != 0 {
            let (block, _remaining) = reader.current_block();
            let mut discard = [0_u8; 8192];
            let mut discarded = 0_usize;
            while offset_in_block > 0 {
                let take_u64 = offset_in_block.min(8192);
                let take = usize::try_from(take_u64).unwrap_or(discard.len());
                XofReader::read(block, &mut discard[..take]);
                discarded += take;
                offset_in_block -= take_u64;
            }
            reader.remaining_in_block -= discarded;
        }
        reader
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

    use super::{ContentReader, block_len, fill_block, fill_block_prefix};
    use crate::{BLOCK_SIZE, ContentSeed, HEADER_SIZE};

    fn seed() -> ContentSeed {
        ContentSeed::from_bytes(*b"0123456789abcdef")
    }

    #[test]
    fn content_reader_remains_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ContentReader>();
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
    #[should_panic(expected = "content block 1 is at most 1048576 bytes")]
    fn fill_block_prefix_rejects_lengths_past_the_block() {
        fill_block_prefix(seed(), 1, &mut vec![0_u8; BLOCK_SIZE + 1]);
    }

    /// The tail of a file is the head of its block: a short squeeze must
    /// equal the full block truncated to the same length.
    #[test]
    fn prefixes_truncate_the_full_block() {
        let mut full = vec![0_u8; block_len(1)];
        fill_block(seed(), 1, &mut full);
        for len in [0, 1, 4096, block_len(1)] {
            let mut prefix = vec![0_u8; len];
            fill_block_prefix(seed(), 1, &mut prefix);
            assert_eq!(prefix, full[..len], "prefix of {len} bytes");
        }
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

    #[test]
    fn offset_reader_matches_a_slice_of_the_complete_stream() {
        let first = block_len(0);
        let offsets = [
            0_u64,
            1,
            first as u64 - 1,
            first as u64,
            first as u64 + 1,
            first as u64 + crate::BLOCK_SIZE as u64,
            first as u64 + crate::BLOCK_SIZE as u64 + 17,
        ];
        let reference_len = usize::try_from(offsets.last().copied().unwrap()).unwrap() + 257;
        let mut reference = vec![0_u8; reference_len];
        ContentReader::new(seed())
            .read_exact(&mut reference)
            .unwrap();

        for offset in offsets {
            let mut actual = [0_u8; 257];
            ContentReader::new_with_offset(seed(), offset)
                .read_exact(&mut actual)
                .unwrap();
            let offset = usize::try_from(offset).unwrap();
            assert_eq!(actual, reference[offset..offset + 257]);
        }
    }

    #[test]
    fn maximum_offset_is_supported_without_overflow() {
        let mut actual = [0_u8; 1];
        ContentReader::new_with_offset(seed(), u64::MAX)
            .read_exact(&mut actual)
            .unwrap();
    }
}
