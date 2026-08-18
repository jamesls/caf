"""Generate golden conformance vectors for the CAF v2 file format.

These vectors capture the byte-level behavior of the CAF version 2 format
so implementations can validate their output against fixed fixtures.

The file vectors are fully deterministic: parent hashes and content seeds
are derived from fixed strings, so re-running this script always produces
the same ``vectors.json``.

The store fixture (``tests/golden/store``) is generated once with the real
``FileGenerator`` (random content seeds) and then committed as fixed data.
Re-generating it produces a different but equally valid store, so the
script refuses to overwrite an existing fixture without ``--force``.

Usage:
    uv run python tests/golden/generate_vectors.py [--force-store]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys

from caf.constants import (
    BLAKE2B_DIGEST_SIZE,
    BLOCK_SIZE,
    CONTENT_DOMAIN,
    CONTENT_SEED_SIZE,
    HEADER_SIZE,
    PARENT_HASH_SIZE,
    ROOT_PARENT_HASH,
)
from caf.content import ContentStream
from caf.generator import FileGenerator
from caf.paths import hash_to_relpath

GOLDEN_DIR = os.path.dirname(os.path.abspath(__file__))
VECTORS_PATH = os.path.join(GOLDEN_DIR, 'vectors.json')
STORE_DIR = os.path.join(GOLDEN_DIR, 'store')

SLICE_SIZE = 32
HALF_SLICE = SLICE_SIZE // 2

# Vector lengths exercise header-only and one-byte content cases. They
# also cover content block boundaries and multiple complete blocks.
FILE_VECTOR_CASES = [
    (
        'header-only',
        'Minimum valid file: 60-byte header, zero content bytes.',
        True,
        HEADER_SIZE,
    ),
    (
        'one-content-byte',
        'Header plus a single content byte (first byte of block 0).',
        False,
        HEADER_SIZE + 1,
    ),
    (
        'end-of-block-0',
        'Content exactly fills block 0; file ends at the 1 MiB boundary.',
        False,
        BLOCK_SIZE,
    ),
    (
        'first-byte-of-block-1',
        'One byte past the 1 MiB boundary; first byte of block 1.',
        True,
        BLOCK_SIZE + 1,
    ),
    (
        'multiple-complete-blocks',
        'Content is exactly block 0 plus two full blocks (3 MiB file).',
        False,
        3 * BLOCK_SIZE,
    ),
    (
        'multi-block-unaligned',
        'Multi-block file that ends mid-block.',
        True,
        2 * BLOCK_SIZE + 4096 + 17,
    ),
]

METADATA_VECTOR_CASES = [
    (
        'single-root',
        ['8843d7f92416211de9ebb963ff4ce28125932878'],
    ),
    (
        'two-roots-sort-order',
        # This deliberately unsorted list verifies that `.metadata/all`
        # hashes the sorted filenames.
        [
            'fa35e192121eabf3dabf9f5ea6abdbcbc107ac3b',
            '9c1185a5c5e9fc54612808977ee8f548b2258d31',
        ],
    ),
    (
        'zero-file-store',
        # A generation run with zero files writes a chain-tip marker
        # named with the hex of the all-zero root parent hash.
        [(b'\x00' * PARENT_HASH_SIZE).hex()],
    ),
]


def derive_seed(name: str) -> bytes:
    return hashlib.sha256(f'caf-golden-seed-{name}'.encode()).digest()[
        :CONTENT_SEED_SIZE
    ]


def derive_parent(name: str) -> bytes:
    return hashlib.sha256(f'caf-golden-parent-{name}'.encode()).digest()[
        :PARENT_HASH_SIZE
    ]


def build_header(
    parent_hash: bytes, content_seed: bytes, file_length: int
) -> bytes:
    """Build a v2 header exactly as FileGenerator does."""
    header = bytearray(HEADER_SIZE)
    header[0:20] = parent_hash
    header[20:36] = content_seed
    header[36:44] = struct.pack('>Q', file_length)
    header[44:52] = hashlib.sha3_256(header[:44]).digest()[:8]
    header[52:60] = b'\x00' * 8
    return bytes(header)


def block_boundaries(file_length: int) -> list[int]:
    """Absolute file offsets where a new content block begins."""
    # Block 0 starts at HEADER_SIZE and ends at BLOCK_SIZE. Each later
    # block N starts at file offset N * BLOCK_SIZE.
    return [offset for offset in range(BLOCK_SIZE, file_length, BLOCK_SIZE)]


def make_file_vector(
    name: str, description: str, is_root: bool, file_length: int
) -> dict:
    parent_hash = ROOT_PARENT_HASH if is_root else derive_parent(name)
    content_seed = derive_seed(name)
    header = build_header(parent_hash, content_seed, file_length)

    content_length = file_length - HEADER_SIZE
    content = ContentStream(content_seed).read(content_length)
    file_bytes = header + content

    digest = hashlib.blake2b(
        file_bytes, digest_size=BLAKE2B_DIGEST_SIZE
    ).hexdigest()

    slices = []

    def add_slice(start: int, end: int) -> None:
        start = max(start, HEADER_SIZE)
        end = min(end, file_length)
        if start >= end:
            return
        entry = {
            'file_offset': start,
            'hex': file_bytes[start:end].hex(),
        }
        if entry not in slices:
            slices.append(entry)

    # First and last content bytes.
    add_slice(HEADER_SIZE, HEADER_SIZE + SLICE_SIZE)
    add_slice(file_length - SLICE_SIZE, file_length)
    # Both sides of every 1 MiB block boundary in the file.
    for boundary in block_boundaries(file_length):
        add_slice(boundary - HALF_SLICE, boundary + HALF_SLICE)
    slices.sort(key=lambda s: s['file_offset'])

    vector = {
        'name': name,
        'description': description,
        'parent_hash': parent_hash.hex(),
        'content_seed': content_seed.hex(),
        'file_length': file_length,
        'header': header.hex(),
        'file_blake2b_160': digest,
        'relative_path': hash_to_relpath(digest).replace(os.sep, '/'),
        'content_slices': slices,
    }
    if file_length <= 128:
        vector['file_hex'] = file_bytes.hex()
    return vector


def make_metadata_vector(name: str, root_names: list[str]) -> dict:
    # FileGenerator._write_root_sha and FileVerifier._verify_known_roots
    # compute BLAKE2b-160 over sorted chain-tip filenames concatenated as
    # ASCII and store the digest as lowercase hex.
    digest = hashlib.blake2b(digest_size=BLAKE2B_DIGEST_SIZE)
    for root in sorted(root_names):
        digest.update(root.encode('ascii'))
    return {
        'name': name,
        'root_names': root_names,
        'all_file_contents': digest.hexdigest(),
    }


def generate_store_fixture() -> None:
    """Generate a small multi-chain store with the real generator."""
    os.makedirs(STORE_DIR, exist_ok=True)
    chains = [
        [60, 61, 1024],  # chain 1: three files, includes minimum size
        [4096, 8192],  # chain 2: two files
    ]
    for sizes in chains:
        remaining = list(sizes)
        generator = FileGenerator(
            STORE_DIR,
            max_files=len(sizes),
            max_disk_usage=None,
            file_size_chooser=lambda: remaining.pop(0),
        )
        generator.generate_files()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        '--force-store',
        action='store_true',
        help='Regenerate the committed store fixture (produces a new, '
        'different-but-valid store).',
    )
    args = parser.parse_args()

    vectors = {
        'description': (
            'Golden conformance vectors for the CAF v2 file format. '
            'Implementations must reproduce every byte and digest.'
        ),
        'constants': {
            'header_size': HEADER_SIZE,
            'block_size': BLOCK_SIZE,
            'block_0_size': BLOCK_SIZE - HEADER_SIZE,
            'content_domain': CONTENT_DOMAIN.decode('ascii'),
            'blake2b_digest_size': BLAKE2B_DIGEST_SIZE,
            'parent_hash_size': PARENT_HASH_SIZE,
            'content_seed_size': CONTENT_SEED_SIZE,
            'root_parent_hash': ROOT_PARENT_HASH.hex(),
        },
        'file_vectors': [
            make_file_vector(*case) for case in FILE_VECTOR_CASES
        ],
        'metadata_vectors': [
            make_metadata_vector(*case) for case in METADATA_VECTOR_CASES
        ],
    }

    with open(VECTORS_PATH, 'w') as f:
        json.dump(vectors, f, indent=2)
        f.write('\n')
    print(f'Wrote {VECTORS_PATH}')

    store_exists = os.path.isdir(STORE_DIR) and os.listdir(STORE_DIR)
    if store_exists and not args.force_store:
        print(f'Store fixture already exists, not touching: {STORE_DIR}')
    else:
        generate_store_fixture()
        print(f'Generated store fixture: {STORE_DIR}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
