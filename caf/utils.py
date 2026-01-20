"""Shared utility functions."""

import os
from contextlib import contextmanager
from typing import Generator


@contextmanager
def cd(directory: str) -> Generator[None, None, None]:
    starting = os.getcwd()
    os.chdir(directory)
    try:
        yield
    finally:
        os.chdir(starting)
