"""Generate independent golden vectors for the CAF version 3 format."""

from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha3_256, shake_128
from pathlib import Path
from typing import Final, TypedDict

from blake3 import blake3

HEADER_SIZE: Final = 60
BLOCK_SIZE: Final = 1 << 20
BLOCK_0_SIZE: Final = BLOCK_SIZE - HEADER_SIZE
CONTENT_DOMAIN: Final = b"caf:content:shake128:v3:"
LEAF_DOMAIN: Final = b"caf:file:leaf:blake3:v3\0"
NODE_DOMAIN: Final = b"caf:file:node:blake3:v3\0"
ROOT_DOMAIN: Final = b"caf:file:root:blake3:v3\0"
FORMAT_MARKER: Final = b"CAF\x03"
FILE_ID_SCHEME: Final = 1
CONTENT_SCHEME: Final = 1
BLOCK_SIZE_LOG_2: Final = 20
FLAGS: Final = 0
DESCRIPTOR: Final = FORMAT_MARKER + bytes(
    [FILE_ID_SCHEME, CONTENT_SCHEME, BLOCK_SIZE_LOG_2, FLAGS]
)
MERKLE_HASH_SIZE: Final = 32
FILE_ID_SIZE: Final = 20
PARENT_FILE_ID_SIZE: Final = 20
CONTENT_SEED_SIZE: Final = 16
ROOT_PARENT_FILE_ID: Final = bytes(PARENT_FILE_ID_SIZE)
SLICE_SIZE: Final = 32


class ContentSlice(TypedDict):
    """One selected slice of physical file content."""

    file_offset: int
    hex: str


class ReductionLevel(TypedDict):
    """All CAF Merkle hashes at one non-leaf tree level."""

    level: int
    hashes: list[str]


class FileVector(TypedDict):
    """Serialized data for one deterministic CAF v3 file."""

    name: str
    description: str
    parent_file_id: str
    content_seed: str
    file_length: int
    block_count: int
    header: str
    content_slices: list[ContentSlice]
    leaf_hashes: list[str]
    reduction_levels: list[ReductionLevel]
    tree_root: str
    full_root: str
    file_id: str
    relative_path: str
    file_hex: str | None


class Constants(TypedDict):
    """Constants pinned by the CAF v3 format."""

    header_size: int
    block_size: int
    block_0_size: int
    block_size_log_2: int
    format_marker_hex: str
    file_id_scheme: int
    content_scheme: int
    flags: int
    descriptor_hex: str
    content_domain: str
    leaf_domain_hex: str
    node_domain_hex: str
    root_domain_hex: str
    merkle_hash_size: int
    file_id_size: int
    parent_file_id_size: int
    content_seed_size: int
    root_parent_file_id: str


class GoldenVectors(TypedDict):
    """Top-level JSON document emitted by this script."""

    description: str
    constants: Constants
    file_vectors: list[FileVector]


@dataclass(frozen=True)
class VectorSpec:
    """Fixed inputs and description for one golden vector."""

    name: str
    description: str
    parent_file_id: bytes
    content_seed: bytes
    file_length: int


VECTOR_SPECS: Final = (
    VectorSpec(
        name="header-only",
        description="Minimum v3 file: one leaf containing only the header.",
        parent_file_id=ROOT_PARENT_FILE_ID,
        content_seed=bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
        file_length=HEADER_SIZE,
    ),
    VectorSpec(
        name="one-content-byte",
        description="Header plus the first v3 content byte in one leaf.",
        parent_file_id=bytes.fromhex(
            "101112131415161718191a1b1c1d1e1f20212223"
        ),
        content_seed=bytes.fromhex("202122232425262728292a2b2c2d2e2f"),
        file_length=HEADER_SIZE + 1,
    ),
    VectorSpec(
        name="one-complete-physical-block",
        description="The file ends exactly at the 1 MiB leaf boundary.",
        parent_file_id=bytes.fromhex(
            "303132333435363738393a3b3c3d3e3f40414243"
        ),
        content_seed=bytes.fromhex("404142434445464748494a4b4c4d4e4f"),
        file_length=BLOCK_SIZE,
    ),
    VectorSpec(
        name="first-byte-of-second-block",
        description="A two-leaf file ending one byte after the boundary.",
        parent_file_id=bytes.fromhex(
            "505152535455565758595a5b5c5d5e5f60616263"
        ),
        content_seed=bytes.fromhex("606162636465666768696a6b6c6d6e6f"),
        file_length=BLOCK_SIZE + 1,
    ),
    VectorSpec(
        name="three-complete-blocks",
        description="Three leaves exercise an odd child in level one.",
        parent_file_id=bytes.fromhex(
            "707172737475767778797a7b7c7d7e7f80818283"
        ),
        content_seed=bytes.fromhex("808182838485868788898a8b8c8d8e8f"),
        file_length=3 * BLOCK_SIZE,
    ),
    VectorSpec(
        name="five-leaf-tree",
        description=(
            "Four complete blocks plus one byte exercise singleton nodes "
            "at two levels."
        ),
        parent_file_id=bytes.fromhex(
            "909192939495969798999a9b9c9d9e9fa0a1a2a3"
        ),
        content_seed=bytes.fromhex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"),
        file_length=4 * BLOCK_SIZE + 1,
    ),
)


def uint64_be(value: int) -> bytes:
    """Encode an unsigned integer as eight big-endian bytes."""

    return value.to_bytes(8, byteorder="big", signed=False)


def encode_header(spec: VectorSpec) -> bytes:
    """Encode the normative 60-byte CAF v3 header."""

    prefix = (
        spec.parent_file_id + spec.content_seed + uint64_be(spec.file_length)
    )
    checksum = sha3_256(prefix + DESCRIPTOR).digest()[:8]
    header = prefix + checksum + DESCRIPTOR
    if len(header) != HEADER_SIZE:
        message = f"encoded header is {len(header)} bytes"
        raise ValueError(message)
    return header


def content_block(seed: bytes, index: int, length: int) -> bytes:
    """Generate a prefix of one independently addressed content block."""

    return shake_128(CONTENT_DOMAIN + seed + uint64_be(index)).digest(length)


def build_file(spec: VectorSpec) -> bytes:
    """Build complete physical file bytes for a fixed vector."""

    file_bytes = bytearray(encode_header(spec))
    remaining = spec.file_length - HEADER_SIZE
    index = 0
    while remaining > 0:
        capacity = BLOCK_0_SIZE if index == 0 else BLOCK_SIZE
        length = min(capacity, remaining)
        file_bytes.extend(content_block(spec.content_seed, index, length))
        remaining -= length
        index += 1
    if len(file_bytes) != spec.file_length:
        message = (
            f"built {len(file_bytes)} bytes for length {spec.file_length}"
        )
        raise ValueError(message)
    return bytes(file_bytes)


def leaf_hash(index: int, block: bytes) -> bytes:
    """Hash one complete or partial physical file block."""

    message = LEAF_DOMAIN + uint64_be(index)
    message += uint64_be(len(block)) + block
    return blake3(message).digest()


def node_hash(level: int, index: int, children: list[bytes]) -> bytes:
    """Hash one internal node with one or two ordered children."""

    if len(children) not in (1, 2):
        message = f"node has {len(children)} children"
        raise ValueError(message)
    message = NODE_DOMAIN + uint64_be(level) + uint64_be(index)
    message += bytes([len(children)]) + b"".join(children)
    return blake3(message).digest()


def reduce_tree(
    leaves: list[bytes],
) -> tuple[list[ReductionLevel], bytes]:
    """Reduce leaf hashes and record every non-leaf tree level."""

    if not leaves:
        raise ValueError("a CAF v3 tree has at least one leaf")
    current = leaves
    reduction_levels: list[ReductionLevel] = []
    level = 1
    while len(current) > 1:
        next_level = [
            node_hash(level, index, current[offset : offset + 2])
            for index, offset in enumerate(range(0, len(current), 2))
        ]
        reduction_levels.append(
            {
                "level": level,
                "hashes": [value.hex() for value in next_level],
            }
        )
        current = next_level
        level += 1
    return reduction_levels, current[0]


def root_hash(
    file_length: int,
    block_count: int,
    tree_root: bytes,
) -> bytes:
    """Bind the block size and file shape into the full v3 root."""

    message = ROOT_DOMAIN + uint64_be(BLOCK_SIZE)
    message += uint64_be(file_length) + uint64_be(block_count)
    return blake3(message + tree_root).digest()


def relative_path(file_id: bytes) -> str:
    """Shard a 20-byte file ID into the CAF relative path layout."""

    encoded = file_id.hex()
    return f"{encoded[:2]}/{encoded[2:4]}/{encoded[4:6]}/{encoded[6:]}"


def selected_content_slices(file_bytes: bytes) -> list[ContentSlice]:
    """Select content starts, physical boundaries, and the file tail."""

    if len(file_bytes) == HEADER_SIZE:
        return []
    offsets = {HEADER_SIZE, max(HEADER_SIZE, len(file_bytes) - SLICE_SIZE)}
    boundary = BLOCK_SIZE
    while boundary < len(file_bytes):
        offsets.add(max(HEADER_SIZE, boundary - SLICE_SIZE // 2))
        boundary += BLOCK_SIZE
    slices: list[ContentSlice] = []
    for offset in sorted(offsets):
        end = min(len(file_bytes), offset + SLICE_SIZE)
        slices.append(
            {
                "file_offset": offset,
                "hex": file_bytes[offset:end].hex(),
            }
        )
    return slices


def make_vector(spec: VectorSpec) -> FileVector:
    """Compute every pinned artifact for one vector specification."""

    file_bytes = build_file(spec)
    leaves = [
        leaf_hash(index, block)
        for index, block in enumerate(
            file_bytes[offset : offset + BLOCK_SIZE]
            for offset in range(0, len(file_bytes), BLOCK_SIZE)
        )
    ]
    levels, tree_root = reduce_tree(leaves)
    full_root = root_hash(spec.file_length, len(leaves), tree_root)
    file_id = full_root[:FILE_ID_SIZE]
    file_hex = file_bytes.hex() if len(file_bytes) <= HEADER_SIZE + 1 else None
    return {
        "name": spec.name,
        "description": spec.description,
        "parent_file_id": spec.parent_file_id.hex(),
        "content_seed": spec.content_seed.hex(),
        "file_length": spec.file_length,
        "block_count": len(leaves),
        "header": file_bytes[:HEADER_SIZE].hex(),
        "content_slices": selected_content_slices(file_bytes),
        "leaf_hashes": [value.hex() for value in leaves],
        "reduction_levels": levels,
        "tree_root": tree_root.hex(),
        "full_root": full_root.hex(),
        "file_id": file_id.hex(),
        "relative_path": relative_path(file_id),
        "file_hex": file_hex,
    }


def constants() -> Constants:
    """Return the fixed constants section of the vector document."""

    return {
        "header_size": HEADER_SIZE,
        "block_size": BLOCK_SIZE,
        "block_0_size": BLOCK_0_SIZE,
        "block_size_log_2": BLOCK_SIZE_LOG_2,
        "format_marker_hex": FORMAT_MARKER.hex(),
        "file_id_scheme": FILE_ID_SCHEME,
        "content_scheme": CONTENT_SCHEME,
        "flags": FLAGS,
        "descriptor_hex": DESCRIPTOR.hex(),
        "content_domain": CONTENT_DOMAIN.decode("ascii"),
        "leaf_domain_hex": LEAF_DOMAIN.hex(),
        "node_domain_hex": NODE_DOMAIN.hex(),
        "root_domain_hex": ROOT_DOMAIN.hex(),
        "merkle_hash_size": MERKLE_HASH_SIZE,
        "file_id_size": FILE_ID_SIZE,
        "parent_file_id_size": PARENT_FILE_ID_SIZE,
        "content_seed_size": CONTENT_SEED_SIZE,
        "root_parent_file_id": ROOT_PARENT_FILE_ID.hex(),
    }


def generate_vectors() -> GoldenVectors:
    """Generate the complete deterministic CAF v3 vector document."""

    return {
        "description": (
            "Independent golden conformance vectors for the CAF v3 file "
            "format. Implementations must reproduce every byte and hash."
        ),
        "constants": constants(),
        "file_vectors": [make_vector(spec) for spec in VECTOR_SPECS],
    }


def main() -> None:
    """Write vectors-v3.json next to this reference implementation."""

    output_path = Path(__file__).with_name("vectors-v3.json")
    rendered = json.dumps(generate_vectors(), indent=2) + "\n"
    output_path.write_text(rendered, encoding="utf-8")
    print(output_path)


if __name__ == "__main__":
    main()
