import hashlib
import json
import os
import struct
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from caf.cli import main
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
from caf.paths import hash_to_relpath, parse_hash_from_path
from caf.verifier import FileVerifier

GOLDEN_DIR = os.path.join(os.path.dirname(__file__), 'golden')
STORE_DIR = os.path.join(GOLDEN_DIR, 'store')

with open(os.path.join(GOLDEN_DIR, 'vectors.json')) as _f:
    VECTORS = json.load(_f)

FILE_VECTORS = VECTORS['file_vectors']
METADATA_VECTORS = VECTORS['metadata_vectors']
FILE_VECTOR_IDS = [v['name'] for v in FILE_VECTORS]
METADATA_VECTOR_IDS = [v['name'] for v in METADATA_VECTORS]


def rebuild_file_bytes(vector: dict[str, Any]) -> bytes:
    header = bytes.fromhex(vector['header'])
    content_length = vector['file_length'] - HEADER_SIZE
    # The odd chunk size verifies that content is invariant under
    # different read patterns.
    stream = ContentStream(bytes.fromhex(vector['content_seed']))
    chunks: list[bytes] = []
    remaining = content_length
    while remaining > 0:
        take = min(65521, remaining)  # prime, not block aligned
        chunks.append(stream.read(take))
        remaining -= take
    return header + b''.join(chunks)


def test_constants_match_version_2_values() -> None:
    frozen = VECTORS['constants']
    assert frozen['header_size'] == HEADER_SIZE
    assert frozen['block_size'] == BLOCK_SIZE
    assert frozen['block_0_size'] == BLOCK_SIZE - HEADER_SIZE
    assert frozen['content_domain'] == CONTENT_DOMAIN.decode('ascii')
    assert frozen['blake2b_digest_size'] == BLAKE2B_DIGEST_SIZE
    assert frozen['parent_hash_size'] == PARENT_HASH_SIZE
    assert frozen['content_seed_size'] == CONTENT_SEED_SIZE
    assert frozen['root_parent_hash'] == ROOT_PARENT_HASH.hex()


@pytest.mark.parametrize('vector', FILE_VECTORS, ids=FILE_VECTOR_IDS)
def test_header_encoding_matches_vector(vector: dict[str, Any]) -> None:
    parent_hash = bytes.fromhex(vector['parent_hash'])
    content_seed = bytes.fromhex(vector['content_seed'])
    header = bytearray(HEADER_SIZE)
    header[0:20] = parent_hash
    header[20:36] = content_seed
    header[36:44] = struct.pack('>Q', vector['file_length'])
    header[44:52] = hashlib.sha3_256(header[:44]).digest()[:8]
    header[52:60] = b'\x00' * 8
    assert bytes(header).hex() == vector['header']


@pytest.mark.parametrize('vector', FILE_VECTORS, ids=FILE_VECTOR_IDS)
def test_content_and_digest_match_vector(vector: dict[str, Any]) -> None:
    file_bytes = rebuild_file_bytes(vector)
    assert len(file_bytes) == vector['file_length']

    digest = hashlib.blake2b(
        file_bytes, digest_size=BLAKE2B_DIGEST_SIZE
    ).hexdigest()
    assert digest == vector['file_blake2b_160']

    for content_slice in vector['content_slices']:
        offset = content_slice['file_offset']
        expected = bytes.fromhex(content_slice['hex'])
        assert file_bytes[offset : offset + len(expected)] == expected

    if 'file_hex' in vector:
        assert file_bytes.hex() == vector['file_hex']


@pytest.mark.parametrize('vector', FILE_VECTORS, ids=FILE_VECTOR_IDS)
def test_relative_path_matches_vector(vector: dict[str, Any]) -> None:
    relpath = hash_to_relpath(vector['file_blake2b_160'])
    assert relpath.replace(os.sep, '/') == vector['relative_path']


@pytest.mark.parametrize(
    'vector',
    [v for v in FILE_VECTORS if v['file_length'] <= 2 * BLOCK_SIZE],
    ids=[
        v['name'] for v in FILE_VECTORS if v['file_length'] <= 2 * BLOCK_SIZE
    ],
)
def test_generator_writes_valid_vector_sized_files(
    vector: dict[str, Any], tmp_path: Path
) -> None:
    generator = FileGenerator(str(tmp_path), 1, None, lambda: 1)
    temp_filename, digest = generator.generate_single_file_enhanced(
        parent_hash=bytes.fromhex(vector['parent_hash']),
        file_size=vector['file_length'],
        buffer_size=FileGenerator.BUFFER_WRITE_SIZE,
        temp_dir=str(tmp_path),
    )
    with open(temp_filename, 'rb') as f:
        file_bytes = f.read()

    assert len(file_bytes) == vector['file_length']
    header = file_bytes[:HEADER_SIZE]
    assert header[:PARENT_HASH_SIZE] == bytes.fromhex(vector['parent_hash'])
    assert struct.unpack('>Q', header[36:44])[0] == vector['file_length']
    assert header[44:52] == hashlib.sha3_256(header[:44]).digest()[:8]
    assert header[52:60] == b'\x00' * 8

    content_seed = header[20:36]
    content_length = vector['file_length'] - HEADER_SIZE
    expected_content = ContentStream(content_seed).read(content_length)
    assert file_bytes[HEADER_SIZE:] == expected_content
    assert (
        digest
        == hashlib.blake2b(
            file_bytes, digest_size=BLAKE2B_DIGEST_SIZE
        ).digest()
    )


@pytest.mark.parametrize('vector', METADATA_VECTORS, ids=METADATA_VECTOR_IDS)
def test_metadata_all_digest_matches_vector(vector: dict[str, Any]) -> None:
    digest = hashlib.blake2b(digest_size=BLAKE2B_DIGEST_SIZE)
    for name in sorted(vector['root_names']):
        digest.update(name.encode('ascii'))
    assert digest.hexdigest() == vector['all_file_contents']


def test_store_fixture_verifies_clean() -> None:
    verifier = FileVerifier(STORE_DIR)
    result = verifier.verify_files()
    assert result.success
    assert result.reports == []


def test_store_fixture_verifies_clean_through_cli() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ['verify', '--directory', STORE_DIR])
    assert result.exit_code == 0, result.output


def test_store_fixture_metadata_all_matches_roots() -> None:
    roots_dir = os.path.join(STORE_DIR, '.metadata', 'roots')
    digest = hashlib.blake2b(digest_size=BLAKE2B_DIGEST_SIZE)
    for name in sorted(os.listdir(roots_dir)):
        digest.update(name.encode('ascii'))
    with open(os.path.join(STORE_DIR, '.metadata', 'all'), 'rb') as f:
        assert f.read() == digest.hexdigest().encode('ascii')


def test_store_fixture_chains_terminate_at_roots() -> None:
    data_files: dict[str, str] = {}
    for root, _, filenames in os.walk(STORE_DIR):
        if '.metadata' in root:
            continue
        for filename in filenames:
            full_path = os.path.join(root, filename)
            file_hash = parse_hash_from_path(full_path)
            assert file_hash, f'unexpected non-CAF path: {full_path}'
            with open(full_path, 'rb') as f:
                parent = f.read(PARENT_HASH_SIZE)
            data_files[file_hash] = parent.hex()

    roots_dir = os.path.join(STORE_DIR, '.metadata', 'roots')
    visited: set[str] = set()
    for tip in os.listdir(roots_dir):
        current = tip
        while current != ROOT_PARENT_HASH.hex():
            assert current in data_files, f'missing chain file: {current}'
            assert current not in visited, 'chains must not share files'
            visited.add(current)
            current = data_files[current]
    assert visited == set(data_files), 'orphaned files in golden store'
