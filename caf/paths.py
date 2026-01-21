"""Helpers for mapping CAF hashes to on-disk paths.

CAF stores files by their BLAKE2b hex digest, sharded into directories:
    {root}/{h[0:2]}/{h[2:4]}/{h[4:6]}/{h[6:]}
"""

from __future__ import annotations

import os

from caf.constants import BLAKE2B_DIGEST_SIZE


SHARD_LEVELS = 3

_SHARD_HEX_CHARS = 2
_HASH_HEX_LENGTH = BLAKE2B_DIGEST_SIZE * 2


def _is_hex(value: str) -> bool:
    return bool(value) and all(c in '0123456789abcdef' for c in value.lower())


def hash_to_relpath(hex_hash: str) -> str:
    """Return the CAF store-relative path for a given hex digest."""
    normalized = hex_hash.lower()
    if len(normalized) != _HASH_HEX_LENGTH:
        raise ValueError(
            f"hex_hash must be {_HASH_HEX_LENGTH} hex characters, got "
            f"{len(normalized)}"
        )
    if not _is_hex(normalized):
        raise ValueError("hex_hash must be lowercase hex characters only")

    shard_chars = SHARD_LEVELS * _SHARD_HEX_CHARS
    shards = [
        normalized[i : i + _SHARD_HEX_CHARS]
        for i in range(0, shard_chars, _SHARD_HEX_CHARS)
    ]
    basename = normalized[shard_chars:]
    return os.path.join(*shards, basename)


def hash_to_path(rootdir: str, hex_hash: str) -> str:
    """Return the full path for a given digest within a CAF store root."""
    return os.path.join(rootdir, hash_to_relpath(hex_hash))


def parse_hash_from_path(path: str) -> str:
    """Extract a CAF hash from an on-disk path.

    Returns the 40-character lowercase hex digest if `path` matches the CAF
    directory layout. Returns an empty string if no match.
    """
    parts = [part for part in path.split(os.sep) if part and part != '.']
    if not parts or '.metadata' in parts:
        return ''

    def matches(shards: list[str], basename: str) -> bool:
        if len(shards) != SHARD_LEVELS:
            return False
        if not all(len(s) == _SHARD_HEX_CHARS and _is_hex(s) for s in shards):
            return False
        expected_basename_len = _HASH_HEX_LENGTH - (
            SHARD_LEVELS * _SHARD_HEX_CHARS
        )
        return len(basename) == expected_basename_len and _is_hex(basename)

    if len(parts) >= 4:
        shards = parts[-4:-1]
        basename = parts[-1]
        if matches(shards, basename):
            return ''.join([s.lower() for s in shards] + [basename.lower()])

    return ''
