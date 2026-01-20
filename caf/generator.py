"""Generate content addressable files with enhanced corruption detection.

The path to each file is the hex digest of the BLAKE2b hash of the file's
contents.

Given the hex digest, the path is split into 3 sub directories consisting of 2
bytes each, and the remaining bytes are used for the file name.

For example, a file with a BLAKE2b hash of "abcdefabcdefabcdefab" would have
a path of "ab/cd/ef/abcdefabcdefab".

File format:
- Parent Hash: 20 bytes (BLAKE2b hash of parent file)
- Content Seed: 16 bytes (random seed for content generation)
- File Length: 8 bytes (total file size in big-endian)
- Header SHA3-256: 8 bytes (first 8 bytes of SHA3-256 hash of bytes 0-43)
- Reserved: 8 bytes (set to 0 for future use)
- Content: Generated deterministically from content seed using SHAKE-128 XOF
"""

import os
import shutil
import tempfile
import hashlib
import struct
from binascii import hexlify
from random import randint
from typing import Callable, Optional

from caf.constants import (
    BLOCK_SIZE,
    CONTENT_SEED_SIZE,
    HEADER_SIZE,
    ROOT_PARENT_HASH,
)
from caf.content import ContentStream
from caf.paths import hash_to_path
from caf.utils import cd


BUFFER_WRITE_SIZE = BLOCK_SIZE
BUFFER_READ_SIZE = BLOCK_SIZE
TEMP_DIR = tempfile.gettempdir()


class FileGenerator(object):
    """Generate random files with enhanced format for corruption detection.

    This class is written such that it's possible to have multiple processes
    running against the same rootdir in parallel.

    This is handled because the files are randomly generated, so the
    chance of collision is extremely small.
    """

    ROOT_HASH = ROOT_PARENT_HASH
    BUFFER_WRITE_SIZE = 1024 * 1024
    ROOTS_DIR = os.path.join('.metadata', 'roots')

    def __init__(
        self,
        rootdir: str,
        max_files: float | None,
        max_disk_usage: float | None,
        file_size_chooser: Callable[[], int],
        buffer_write_size: int = BUFFER_WRITE_SIZE,
        temp_dir: Optional[str] = None,
    ) -> None:
        if max_files is None:
            max_files = float('inf')
        if max_disk_usage is None:
            max_disk_usage = float('inf')
        self._rootdir = rootdir
        self._max_files: float = max_files
        self._max_disk_usage: float = max_disk_usage
        self._file_size_chooser = file_size_chooser
        self._buffer_write_size = buffer_write_size
        self._temp_dir = temp_dir
        self._created_dirs: set[str] = set()

    def generate_files(self) -> None:
        temp_dir = self._temp_dir
        if temp_dir is None:
            # Use rootdir for temp files to ensure same filesystem.
            temp_dir = self._rootdir
        with cd(self._rootdir):
            files_created = 0
            file_size_chooser = self._file_size_chooser
            disk_space_bytes_used = 0
            parent_hash = self.ROOT_HASH

            while (
                files_created < self._max_files
                and disk_space_bytes_used < self._max_disk_usage
            ):
                file_size = file_size_chooser()
                # Ensure minimum file size for header
                if file_size < HEADER_SIZE:
                    file_size = HEADER_SIZE

                temp_filename, blake2b_hash = (
                    self.generate_single_file_enhanced(
                        parent_hash,
                        file_size=file_size,
                        buffer_size=self.BUFFER_WRITE_SIZE,
                        temp_dir=temp_dir,
                    )
                )
                ascii_hex_basename = hexlify(blake2b_hash).decode("ascii")
                self._move_to_final_location(temp_filename, ascii_hex_basename)
                files_created += 1
                disk_space_bytes_used += file_size
                parent_hash = blake2b_hash

            # Write out the root file in the special metadata/roots/ directory
            self._write_root_sha(hexlify(parent_hash).decode("ascii"))

    def generate_single_file_enhanced(
        self,
        parent_hash: bytes,
        file_size: int,
        buffer_size: int,
        temp_dir: str,
    ) -> tuple[str, bytes]:
        """Generate a single file with the enhanced format."""
        # Ensure minimum file size
        if file_size < HEADER_SIZE:
            file_size = HEADER_SIZE

        # Generate content seed
        content_seed = os.urandom(CONTENT_SEED_SIZE)

        # Create header
        header = bytearray(HEADER_SIZE)
        header[0:20] = parent_hash
        header[20:36] = content_seed
        header[36:44] = struct.pack('>Q', file_size)
        # Calculate header checksum (SHA3-256 of first 44 bytes)
        header_checksum = hashlib.sha3_256(header[:44]).digest()[:8]
        header[44:52] = header_checksum
        # Reserved bytes (zeros)
        header[52:60] = b'\x00' * 8

        # Generate content using SHAKE-128 (streamed, constant-memory).
        content_length = file_size - HEADER_SIZE

        # Generate temp filename
        temp_filename = os.path.join(
            temp_dir,
            hexlify(parent_hash[:8]).decode('ascii') + str(randint(1, 100000)),
        )

        # Calculate BLAKE2b hash of entire file while writing.
        blake2b = hashlib.blake2b(digest_size=20)

        with open(temp_filename, 'wb') as f:
            # Write header
            f.write(header)
            blake2b.update(header)

            # Write content in chunks (avoids materializing whole file).
            # ContentStream internally aligns blocks so that block 0 is
            # (buffer_size - HEADER_SIZE) and subsequent blocks are
            # buffer_size, ensuring blocks 1..N start at aligned offsets.
            stream = ContentStream(content_seed)
            remaining = content_length
            while remaining > 0:
                chunk_size = min(buffer_size, remaining)
                chunk = stream.read(chunk_size)
                f.write(chunk)
                blake2b.update(chunk)
                remaining -= chunk_size

        return temp_filename, blake2b.digest()

    def _write_root_sha(self, filename: str) -> None:
        directory_name = os.path.join(self._rootdir, self.ROOTS_DIR)
        self._ensure_directory(directory_name)
        with open(os.path.join(directory_name, filename), 'w') as f:
            pass
        # Calculate hash of all root files
        roots_hash = hashlib.blake2b(digest_size=20)
        for filename in sorted(os.listdir(directory_name)):
            roots_hash.update(filename.encode('ascii'))
        final_roots_hash = roots_hash.hexdigest()
        with open(os.path.join(self._rootdir, '.metadata', 'all'), 'wb') as f:
            f.write(final_roots_hash.encode('ascii'))

    def _ensure_directory(self, dir_path: str) -> None:
        """Create directory if not already created this session."""
        if dir_path in self._created_dirs:
            return
        os.makedirs(dir_path, exist_ok=True)
        self._created_dirs.add(dir_path)

    def _move_to_final_location(
        self, temp_filename: str, ascii_hex_basename: str
    ) -> None:
        final_filename = hash_to_path(self._rootdir, ascii_hex_basename)
        directory_part = os.path.dirname(final_filename)
        self._ensure_directory(directory_part)
        shutil.move(temp_filename, final_filename)
