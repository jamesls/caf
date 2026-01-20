# CAF File Format Specification

This document describes the structure of Content Addressable Files (CAF) v2 format.

## Overview

CAF files are deterministically generated content files designed for storage system
testing and validation. Each file consists of a 60-byte header followed by
SHAKE-128 generated content. Files are identified by their BLAKE2b hash and can
be chained together via parent references.

## File Structure

```
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                                                               +
   |                                                               |
   +                        Parent Hash                            +
   |                        (20 bytes)                             |
   +                                                               +
   |                                                               |
   +                                                               +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                                                               +
   |                                                               |
   +                        Content Seed                           +
   |                        (16 bytes)                             |
   +                                                               +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                     File Length (uint64 BE)                   +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                       Header Checksum                         +
   |                  (first 8 bytes of SHA3-256)                  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                         Reserved                              +
   |                        (8 bytes)                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                                                               +
   |                                                               |
   +                         Content                               +
   |                  (file_length - 60 bytes)                     |
   +                                                               +
   |                           ...                                 |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

## Header Fields

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 20 | Parent Hash | BLAKE2b hash of parent file (zeros for root files) |
| 20 | 16 | Content Seed | Random seed for deterministic content generation |
| 36 | 8 | File Length | Total file size including header (big-endian uint64) |
| 44 | 8 | Header Checksum | First 8 bytes of SHA3-256(header[0:44]) |
| 52 | 8 | Reserved | Reserved for future use (all zeros) |

**Total Header Size: 60 bytes**

### Parent Hash

The parent hash field links files together in a chain. Root files (the first
file in a chain) use all zeros (`0x00 * 20`). Child files contain the BLAKE2b
hash of their parent file, allowing verification of file relationships.

### Content Seed

A random 16-byte value that seeds the SHAKE-128 XOF for content generation.
The same seed always produces identical content, making files fully
deterministic and verifiable.

### File Length

The total file size in bytes, stored as an unsigned 64-bit big-endian integer.
This includes the 60-byte header, so the minimum valid value is 60.

### Header Checksum

Integrity check for the header fields. Computed as the first 8 bytes of the
SHA3-256 hash of header bytes 0-43 (parent hash + content seed + file length).

### Reserved

Eight bytes reserved for future format extensions. Must be all zeros in v2.

## Content Generation

Content is deterministically generated from the content seed using SHAKE-128:

```
domain = b"caf:content:shake128:v2:"

for each block_index:
    block_data = SHAKE128(domain + content_seed + block_index_bytes).digest(block_size)
```

Where `block_index_bytes` is the block index as an 8-byte big-endian integer.

### Block Alignment

Content is generated in blocks for efficient streaming:

- **Block 0**: 1,048,516 bytes (1MB - 60 bytes header)
- **Blocks 1+**: 1,048,576 bytes (1MB)

This ensures blocks 1 and onwards start at 1MB-aligned file offsets for
optimal I/O performance.

## File Identification

Files are identified by their BLAKE2b hash (20-byte digest) computed over
the entire file contents (header + content). The hex-encoded hash serves as
the filename in the content-addressable storage structure:

```
{root}/{hash[0:2]}/{hash[2:4]}/{hash[4:6]}/{hash[6:]}
```

Example: hash `abcdef0123456789abcdef0123456789abcdef01` is stored at `ab/cd/ef/0123456789abcdef0123456789abcdef01`

## Validation

A CAF file is valid if:

1. File size >= 60 bytes
2. File length field matches actual file size
3. Header checksum matches SHA3-256(header[0:44])[0:8]
4. Content matches SHAKE-128 output for the given content seed
5. Parent hash references an existing file (or is all zeros for roots)

## Constants

```python
HEADER_SIZE = 60
BLOCK_SIZE = 1048576  # 1MB
BLAKE2B_DIGEST_SIZE = 20
PARENT_HASH_SIZE = 20
CONTENT_SEED_SIZE = 16
CONTENT_DOMAIN = b"caf:content:shake128:v2:"
ROOT_PARENT_HASH = b'\x00' * 20
```
