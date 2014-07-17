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
import shutil
from binascii import hexlify
from random import randint
import tempfile
import hashlib
from contextlib import contextmanager

BUFFER_WRITE_SIZE = 1024 * 1024
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
                    final_filename = os.path.join(
                        self._rootdir, hexlify(sha1_hash).decode('ascii'))
                    os.rename(temp_filename, final_filename)
                    files_created += 1
                    disk_space_bytes_used += file_size
        finally:
            if delete_temp_dir:
                shutil.rmtree(temp_dir)

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
