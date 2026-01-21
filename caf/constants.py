"""CAF format specification constants.

WARNING: These constants define the CAF file format. Changing any of these
values will produce incompatible files that cannot be verified by other
implementations. Only modify these values when creating a new format version.

Format Version: v2 (shake128)
"""

# ====================
# HEADER SPECIFICATION
# ====================

# Total size of the file header in bytes.
# Layout:
#   - Bytes 0-19:  Parent hash (BLAKE2b, 20 bytes)
#   - Bytes 20-35: Content seed (random, 16 bytes)
#   - Bytes 36-43: File length (big-endian uint64, 8 bytes)
#   - Bytes 44-51: Header checksum (SHA3-256 truncated, 8 bytes)
#   - Bytes 52-59: Reserved (zeros, 8 bytes)
HEADER_SIZE = 60

# ================================
# CONTENT GENERATION SPECIFICATION
# ================================

# Size of content blocks for deterministic generation.
# Block 0 is (BLOCK_SIZE - HEADER_SIZE) bytes to align subsequent blocks
# to BLOCK_SIZE boundaries in the file for optimal I/O performance.
BLOCK_SIZE = 1024 * 1024  # 1MB

# Domain separation string for SHAKE-128 content generation.
# Format: "caf:content:{algorithm}:{version}:"
CONTENT_DOMAIN = b"caf:content:shake128:v2:"

# ===================
# HASH SPECIFICATIONS
# ===================

# BLAKE2b digest size for file identification (filename = hex of this hash).
BLAKE2B_DIGEST_SIZE = 20

# Size of parent hash field in header (same as BLAKE2B_DIGEST_SIZE).
PARENT_HASH_SIZE = 20

# Root files use this value for their parent hash field.
ROOT_PARENT_HASH = b'\x00' * PARENT_HASH_SIZE

# Content seed size for content generation.
CONTENT_SEED_SIZE = 16
