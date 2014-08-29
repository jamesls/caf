"""Verify files generated from the caf.generator module."""
import os
import sys
from binascii import hexlify
import hashlib

from caf.utils import file_path_to_hash


BUFFER_READ_SIZE = 1024 * 1024


class FileVerifier(object):
    ROOTS_DIR = os.path.join('.metadata', 'roots')

    def __init__(self, rootdir):
        self._rootdir = rootdir

    def verify_files(self):
        referenced = set()
        known_roots = os.listdir(os.path.join(self._rootdir, self.ROOTS_DIR))
        files_validated = 0
        for root, _, filenames in os.walk(self._rootdir):
            if '.metadata' in root:
                # We validate the metadata directory separately.
                continue
            for filename in filenames:
                full_path = os.path.join(root, filename)
                self._validate_checksum(full_path)
                files_validated += 1
                parent_full_path = self._get_parent_file(full_path)
                referenced.add(parent_full_path)
                if parent_full_path is not None and \
                        not os.path.isfile(parent_full_path):
                    sys.stderr.write(
                        "CORRUPTION: Parent hash not found: %s\n" % (
                            parent_full_path))
        self._verify_referenced_files(referenced, known_roots)
        self._verify_known_roots(known_roots)

    def _verify_known_roots(self, known_roots):
        verify_hash = hashlib.sha1()
        for root in known_roots:
            verify_hash.update(root.encode('ascii'))
        actual = verify_hash.hexdigest().encode('ascii')
        with open(os.path.join(self._rootdir, '.metadata', 'all'), 'rb') as f:
            expected = f.read()
        if actual != expected:
            sys.stderr.write("CORRUPTION: Root hash is not valid, roots are "
                             "missing.\n")

    def _verify_referenced_files(self, referenced, known_roots):
        for root, _, filenames in os.walk(self._rootdir):
            if '.metadata' in root:
                continue
            for filename in filenames:
                full_path = os.path.join(root, filename)
                if full_path not in referenced and \
                        file_path_to_hash(full_path) not in known_roots:
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
        expected_sha1 = ''.join(filename.split(os.sep)[-3:])
        with open(filename, 'rb') as f:
            for chunk in iter(lambda: f.read(BUFFER_READ_SIZE), b''):
                sha1.update(chunk)
        actual = sha1.hexdigest()
        if actual != expected_sha1:
            # Better error message.
            sys.stderr.write(
                'CORRUPTION: Invalid checksum for file "%s": '
                'actual sha1 %s\n' % (filename, actual))
