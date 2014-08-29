"""Generate content addressable files.

The path to each file is the hex digest of the sha1 of the file's contents.

Given the hex digest, the path is split into 4 sub directories consisting of 1
byte each, and the remaining 16 bytes are used for the file name.

For example, a file with a sha1 of "abcdefabcdefabcd" would have a path of
"ab/cd/ef/ab/cdefabcd".

As for the contents of the file, each file has the sha1 of the parent file
as the first 20 bytes, followed by randomly generated content.


"""
import os
from binascii import hexlify
from random import randint
import tempfile
import hashlib

from caf.utils import cd


BUFFER_WRITE_SIZE = 1024 * 1024
BUFFER_READ_SIZE = 1024 * 1024
TEMP_DIR = tempfile.gettempdir()


class FileGenerator(object):
    """Generate random files.

    This class is written such that it's possible to have multiple processes
    running against the same rootdir in parallel.

    This is handled because the files are randomly generated, so the
    chance of collision is extremely small.
    """

    ROOT_HASH = b'\x00' * 20
    BUFFER_WRITE_SIZE = 1024 * 1024
    ROOTS_DIR = os.path.join('.metadata', 'roots')

    def __init__(self, rootdir, max_files, max_disk_usage,
                 file_size_chooser, buffer_write_size=BUFFER_WRITE_SIZE,
                 temp_dir=None):
        if max_files is None:
            max_files = float('inf')
        if max_disk_usage is None:
            max_disk_usage = float('inf')
        self._rootdir = rootdir
        self._max_files = max_files
        self._max_disk_usage = max_disk_usage
        self._file_size_chooser = file_size_chooser
        self._buffer_write_size = buffer_write_size
        self._temp_dir = temp_dir

    def generate_files(self):
        temp_dir = self._temp_dir
        if temp_dir is None:
            # Use the current woroking directory as the
            # temp dir.
            temp_dir = os.getcwd()
        with cd(self._rootdir):
            files_created = 0
            file_size_chooser = self._file_size_chooser
            disk_space_bytes_used = 0
            sha1_hash = self.ROOT_HASH
            while files_created < self._max_files and \
                    disk_space_bytes_used < self._max_disk_usage:
                file_size = file_size_chooser()
                temp_filename, sha1_hash = self.generate_single_file_link(
                    sha1_hash, file_size=file_size,
                    buffer_size=self.BUFFER_WRITE_SIZE,
                    temp_dir=temp_dir)
                ascii_hex_basename = hexlify(sha1_hash).decode('ascii')
                self._move_to_final_location(
                    temp_filename, ascii_hex_basename)
                files_created += 1
                disk_space_bytes_used += file_size
            # Write out the root file in the special
            # metadata/roots/ directory so we know when
            # we validate that this file is not suppose
            # to have anything referring to it.
            self._write_root_sha(ascii_hex_basename)

    def _write_root_sha(self, filename):
        directory_name = os.path.join(self._rootdir, self.ROOTS_DIR)
        if not os.path.isdir(directory_name):
            try:
                os.makedirs(directory_name)
            except OSError:
                pass
        assert os.path.isdir(directory_name)
        with open(os.path.join(directory_name, filename), 'w') as f:
            pass
        # This is the only part we have to lock.  If we have multiple roots
        # being written out, the only way we can validate that an entire
        # chain from root->start hasn't been completely removed (even though
        # it's extremely unlikely) is to have a file that can be used
        # to validate that all the root file are accounted for.
        # TODO: Actually lock the file.
        roots_hash = hashlib.sha1()
        for filename in os.listdir(directory_name):
            roots_hash.update(filename.encode('ascii'))
        final_roots_hash = roots_hash.hexdigest()
        with open(os.path.join(self._rootdir, '.metadata', 'all'), 'wb') as f:
            f.write(final_roots_hash.encode('ascii'))

    def _move_to_final_location(self, temp_filename, ascii_hex_basename):
        # This is not exposed as a config option (yet),
        # given a full sha1 hash, this translates to:
        #
        #   ab/cd/<remaining hash>
        directory_part = os.path.join(
            self._rootdir, ascii_hex_basename[:2],
            ascii_hex_basename[2:4])
        basename = ascii_hex_basename[4:]
        if not os.path.isdir(directory_part):
            try:
                os.makedirs(directory_part)
            except OSError:
                pass
        assert os.path.isdir(directory_part)
        final_filename = os.path.join(directory_part, basename)
        os.rename(temp_filename, final_filename)

    def generate_single_file_link(self, parent_hash, file_size,
                                  buffer_size, temp_dir):
        sha1 = hashlib.sha1(parent_hash)
        amount_remaining = file_size
        temp_filename = os.path.join(
            temp_dir,
            hexlify(parent_hash[:8]).decode('ascii') + str(randint(1, 100000)))

        with open(temp_filename, 'wb') as f:
            f.write(parent_hash)
            amount_remaining -= len(parent_hash)
            while amount_remaining > 0:
                chunk_size = min(buffer_size, amount_remaining)
                random_data = os.urandom(chunk_size)
                f.write(random_data)
                sha1.update(random_data)
                amount_remaining -= chunk_size
        return temp_filename, sha1.digest()
