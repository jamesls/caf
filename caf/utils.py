"""Shared utility functions."""

import os
from contextlib import contextmanager
from typing import Generator


def file_path_to_hash(filename: str) -> str:
    """Convert a BLAKE2b file name to the original BLAKE2b hash.

    Given a full filename such as "/path/to/rootdir/ab/cd/ef/ab/cdeffffff...",
    this function will extract just the CAF path components and convert
    them to the original BLAKE2b string hash: "abcdefabcdeffffff"
    """
    # Split the path and find the CAF directory structure
    parts = filename.split(os.sep)

    # Find the last 5 parts (xx/yy/zz/ww/filename) that form the hash
    # Skip any absolute path prefix and metadata directories
    caf_parts = []
    for i in range(len(parts)):
        part = parts[i]
        # Skip empty parts, metadata, and non-hex parts
        if (
            not part
            or part == '.'
            or '.metadata' in part
            or len(part) != 2
            or not all(c in '0123456789abcdef' for c in part.lower())
        ):
            continue

        # If we find a 2-character hex part, collect it and the next 4 parts
        if i + 4 < len(parts) and all(
            len(parts[j]) == 2
            and all(c in '0123456789abcdef' for c in parts[j].lower())
            for j in range(i, i + 4)
        ):
            # Found the start of CAF structure: collect 4 dirs + filename
            caf_parts = parts[i : i + 5]
            break

    if not caf_parts:
        # Fallback: try to extract from the end of the path
        # Look for pattern where last 5 parts could form a hash
        if len(parts) >= 5:
            caf_parts = parts[-5:]

    return ''.join(caf_parts)


@contextmanager
def cd(directory: str) -> Generator[None, None, None]:
    starting = os.getcwd()
    os.chdir(directory)
    try:
        yield
    finally:
        os.chdir(starting)
