"""Shared utility functions."""
import os
from contextlib import contextmanager


def file_path_to_hash(filename):
    """Convert a sha1 file name to the original sha1.

    Given a full filename such as "ab/cd/effffff...",
    this function will convert it to the original sha1
    string hash:  "abcdefffff"
    """
    # .strip('.') because a relative path may come in like
    # './ab/cd/efff'
    return ''.join(filename.split(os.sep)).strip('.')


@contextmanager
def cd(directory):
    starting = os.getcwd()
    os.chdir(directory)
    try:
        yield
    finally:
        os.chdir(starting)
