"""Deterministic content generation utilities.

CAF files store a content seed in the header. File content is derived
deterministically from that seed so verifiers can regenerate expected bytes and
pinpoint corruption without external data.

The stdlib hashlib SHAKE APIs don't support streaming output, so we implement a
stream using fixed-size blocks derived from
SHAKE-128(content_seed || block_index).
Block 0 is sized (BLOCK_SIZE - HEADER_SIZE) to align subsequent blocks
to BLOCK_SIZE boundaries in the file. This improves I/O performance.
"""

from __future__ import annotations

import hashlib

from caf.constants import (
    BLOCK_SIZE,
    CONTENT_DOMAIN,
    HEADER_SIZE,
    CONTENT_SEED_SIZE,
)


class ContentStream:
    """Generate an infinite deterministic byte stream from a content seed.

    Uses SHAKE-128 XOF for fast, deterministic content generation.
    Blocks are generated at fixed sizes to ensure content is deterministic
    regardless of read() call pattern.

    Block 0 is sized (BLOCK_SIZE - HEADER_SIZE) so that subsequent
    blocks align to BLOCK_SIZE boundaries in the file.
    """

    def __init__(self, content_seed: bytes) -> None:
        if len(content_seed) != CONTENT_SEED_SIZE:
            raise ValueError(f"content_seed must be {CONTENT_SEED_SIZE} bytes")

        self._content_seed = content_seed
        self._block_index = 0
        self._block = b""
        self._block_pos = 0

    def _block_size(self, index: int) -> int:
        """Return the size of block at given index."""
        if index == 0:
            return BLOCK_SIZE - HEADER_SIZE
        return BLOCK_SIZE

    def read(self, length: int) -> bytes:
        """Return the next `length` bytes from the stream."""
        if length < 0:
            raise ValueError("length must be non-negative")
        if length == 0:
            return b""

        output = bytearray()
        while len(output) < length:
            # Use any remaining bytes from current block first
            if self._block_pos < len(self._block):
                take = min(
                    length - len(output), len(self._block) - self._block_pos
                )
                output += self._block[self._block_pos : self._block_pos + take]
                self._block_pos += take
                continue

            # Generate next block at fixed size
            block_size = self._block_size(self._block_index)
            self._block = self._generate_block(self._block_index, block_size)
            self._block_index += 1
            self._block_pos = 0

        return bytes(output)

    def _generate_block(self, index: int, size: int) -> bytes:
        block_index_bytes = index.to_bytes(8, byteorder="big", signed=False)
        shake = hashlib.shake_128(
            CONTENT_DOMAIN + self._content_seed + block_index_bytes
        )
        return shake.digest(size)
