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
import sys
import shutil
from binascii import hexlify
from random import randint
import tempfile
import hashlib
from contextlib import contextmanager

BUFFER_WRITE_SIZE = 1024 * 1024
BUFFER_READ_SIZE = 1024 * 1024
TEMP_DIR = tempfile.gettempdir()


@contextmanager
def cd(directory):
    starting = os.getcwd()
    os.chdir(directory)
    try:
        yield
    finally:
        os.chdir(starting)


class FileGenerator(object):
    """Generate random files."""

    ROOT_HASH = b'\x00' * 20
    BUFFER_WRITE_SIZE = 1024 * 1024

    def __init__(self, rootdir, max_files, max_disk_usage,
                 file_size, buffer_write_size=BUFFER_WRITE_SIZE,
                 temp_dir=None):
        if max_files is None:
            max_files = float('inf')
        if max_disk_usage is None:
            max_disk_usage = float('inf')
        self._rootdir = rootdir
        self._max_files = max_files
        self._max_disk_usage = max_disk_usage
        self._file_size = file_size
        self._buffer_write_size = buffer_write_size
        self._temp_dir = temp_dir

    def generate_files(self):
        temp_dir = self._temp_dir
        delete_temp_dir = False
        if temp_dir is None:
            temp_dir = tempfile.mkdtemp()
            delete_temp_dir = True
        try:
            with cd(self._rootdir):
                files_created = 0
                file_size = self._file_size
                disk_space_bytes_used = 0
                sha1_hash = self.ROOT_HASH
                while files_created < self._max_files and \
                        disk_space_bytes_used < self._max_disk_usage:
                    temp_filename, sha1_hash = self.generate_single_file_link(
                        sha1_hash, file_size=file_size,
                        buffer_size=self.BUFFER_WRITE_SIZE,
                        temp_dir=temp_dir)
                    ascii_hex_basename = hexlify(sha1_hash).decode('ascii')
                    self._move_to_final_location(
                        temp_filename, ascii_hex_basename)
                    files_created += 1
                    disk_space_bytes_used += file_size
        finally:
            if delete_temp_dir:
                shutil.rmtree(temp_dir)

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
            while amount_remaining > 0:
                chunk_size = min(buffer_size, amount_remaining)
                random_data = os.urandom(chunk_size)
                f.write(random_data)
                sha1.update(random_data)
                amount_remaining -= chunk_size
        return temp_filename, sha1.digest()


class FileVerifier(object):
    def __init__(self, rootdir):
        self._rootdir = rootdir

    def verify_files(self):
        referenced = set()
        files_validated = 0
        for root, dirnames, filenames in os.walk(self._rootdir):
            for filename in filenames:
                full_path = os.path.join(root, filename)
                self._validate_checksum(full_path)
                files_validated += 1
                parent_full_path = self._get_parent_file(full_path)
                referenced.add(parent_full_path)
                if parent_full_path is not None and \
                        not os.path.isfile(parent_full_path):
                    sys.stderr.write("CORRUPTION: Parent hash not found: %s\n" % (
                        parent_full_path))
        self._verify_referenced_files(referenced)

    def _verify_referenced_files(self, referenced):
        for root, _, filenames in os.walk(self._rootdir):
            for filename in filenames:
                full_path = os.path.join(root, filename)
                if full_path not in referenced:
                    sys.stderr.write(
                        "CORRUPTION: File not referenced by any files: %s\n" %
                        (full_path))

    def _get_parent_file(self, full_path):
        with open(full_path, 'rb') as f:
            binary_sha1 = f.read(20)
            if binary_sha1 == b'\x00' * 20:
                # This is the root file so it has no parent hash.
                return None
            hex_sha1 = hexlify(binary_sha1).decode('ascii')
            return os.path.join(self._rootdir,
                                hex_sha1[:2],
                                hex_sha1[2:4],
                                hex_sha1[4:])

    def _validate_checksum(self, filename):
        sha1 = hashlib.sha1()
        bname = os.path.basename
        expected_sha1 = ''.join(filename.split(os.sep)[-3:])
        with open(filename, 'rb') as f:
            for chunk in iter(lambda: f.read(BUFFER_READ_SIZE), b''):
                sha1.update(chunk)
        actual = sha1.hexdigest()
        if actual != expected_sha1:
            # Better error message.
            sys.stderr.write(
                'CORRUPTION: Invalid checksum for file "%s": actual sha1 %s\n' % (
                    filename, actual))


# if __name__ == '__main__':
#
#
#     # Demo of generating the random content.
#     temp_filename, sha1_hash = generate_single_file_link(
#         b'\x00' * 20, file_size=4048)
#     final_filename = os.path.join(b'test', hexlify(sha1_hash))
#     os.rename(temp_filename, final_filename)
#     print("Generating:", final_filename)
#     for _ in range(10):
#         temp_filename, sha1_hash = generate_single_file_link(
#             sha1_hash, file_size=4048)
#         final_filename = os.path.join(b'test', hexlify(sha1_hash))
#         os.rename(temp_filename, final_filename)
#         print("Generating:", final_filename)
#     print('\n')
#     # Demo of verifying
#     current_filename = final_filename
#     while os.path.basename(current_filename) != b'0' * 40:
#         # First verify that sha1(current_filename) == current_filename
#         print("Verifying", current_filename)
#         with open(current_filename, 'rb') as f:
#             actual = hashlib.sha1(f.read()).hexdigest().encode('ascii')
#             expected = os.path.basename(current_filename)
#             if actual != expected:
#                 import pdb; pdb.set_trace()
#             f.seek(0)
#             current_filename = os.path.join(b'test', hexlify(f.read(20)))
