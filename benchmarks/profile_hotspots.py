"""Profile the Python implementation's hot paths.

Runs generation, clean verification, and corrupted verification under
cProfile and divides self-time among SHAKE generation, BLAKE2b hashing,
SHA3 header checksums, file I/O, filesystem metadata operations, store walking,
corruption analysis, and terminal rendering. (Process-pool startup and
interprocess serialization do not apply: the Python implementation is
single-process.)

Writes per-scenario text reports and a category summary JSON to
``benchmarks/results/``.

Usage:
    uv run python benchmarks/profile_hotspots.py
"""

from __future__ import annotations

import cProfile
import io
import json
import os
import pstats
import random
import shutil
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from typing import Callable

from caf.generator import FileGenerator
from caf.verifier import FileVerifier

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_DIR = os.path.join(REPO_ROOT, 'benchmarks', 'results')

SMALL_FILES = 10_000
SMALL_SIZE = 4096
LARGE_FILES = 32
LARGE_SIZE = 8 * 1024 * 1024
CORRUPT_COUNT = 20
CORRUPT_LENGTH = 4096

# Category matchers apply to pstats function descriptions. More specific
# patterns appear first.
CATEGORY_MATCHERS: list[tuple[str, str]] = [
    ('shake', '_sha3.shake_128'),
    ('shake', '_hashlib.HASHXOF'),
    ('shake', 'openssl_shake_128'),
    ('sha3_header_checksum', '_sha3.sha3_256'),
    ('sha3_header_checksum', 'openssl_sha3_256'),
    ('sha3_header_checksum', "of '_hashlib.HASH' objects"),
    ('blake2b', '_blake2'),
    ('os_urandom', 'posix.urandom'),
    ('file_io', " of '_io"),
    ('file_io', 'io.open'),
    ('fs_metadata', 'posix.rename'),
    ('fs_metadata', 'posix.mkdir'),
    ('fs_metadata', 'posix.stat'),
    ('fs_metadata', 'posix.lstat'),
    ('fs_metadata', 'posix.listdir'),
    ('store_walk', 'posix.scandir'),
    ('store_walk', 'os.py'),
    ('rendering', 'rich/'),
    ('corruption_analysis', 'verifier.py'),
    ('content_stream_py', 'content.py'),
    ('generator_py', 'generator.py'),
    ('paths_py', 'paths.py'),
]


def categorize(description: str) -> str:
    for category, needle in CATEGORY_MATCHERS:
        if needle in description:
            return category
    return 'other'


def category_split(stats: pstats.Stats) -> dict[str, float]:
    totals: dict[str, float] = {}
    for func, (_, _, tottime, _, _) in stats.stats.items():
        filename, lineno, name = func
        description = f'{filename}:{lineno}({name})'
        category = categorize(description)
        totals[category] = totals.get(category, 0.0) + tottime
    return dict(sorted(totals.items(), key=lambda item: item[1], reverse=True))


def profile_scenario(
    name: str, action: Callable[[], None]
) -> dict[str, float]:
    profiler = cProfile.Profile()
    profiler.enable()
    action()
    profiler.disable()

    stats = pstats.Stats(profiler)
    report_path = os.path.join(RESULTS_DIR, f'profile-{name}.txt')
    with open(report_path, 'w') as f:
        stream_stats = pstats.Stats(profiler, stream=f)
        stream_stats.sort_stats('cumulative').print_stats(30)
        stream_stats.sort_stats('tottime').print_stats(30)

    split = category_split(stats)
    total = sum(split.values()) or 1.0
    print(f'--- {name} (profiled self-time split)')
    for category, seconds in split.items():
        print(f'  {category:22s} {seconds:8.2f}s {seconds / total:6.1%}')
    print(f'  report: {report_path}')
    return {k: round(v, 3) for k, v in split.items()}


def generate(rootdir: str, count: int, size: int) -> None:
    os.makedirs(rootdir, exist_ok=True)
    FileGenerator(
        rootdir,
        max_files=count,
        max_disk_usage=None,
        file_size_chooser=lambda: size,
    ).generate_files()


def corrupt_some(rootdir: str) -> None:
    files = []
    for root, dirnames, filenames in os.walk(rootdir):
        dirnames[:] = [d for d in dirnames if d != '.metadata']
        files.extend(os.path.join(root, f) for f in filenames)
    rng = random.Random(0x5CAF)
    for path in rng.sample(sorted(files), min(CORRUPT_COUNT, len(files))):
        size = os.path.getsize(path)
        length = min(CORRUPT_LENGTH, max(1, size - 60))
        offset = 60 + max(0, (size - 60 - length) // 2)
        with open(path, 'r+b') as f:
            f.seek(offset)
            original = f.read(length)
            f.seek(offset)
            f.write(bytes(b ^ 0xFF for b in original))


def verify(rootdir: str, expect_success: bool) -> None:
    # Redirect rendering so terminal speed does not affect the profile.
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        result = FileVerifier(rootdir).verify_files()
    if result.success != expect_success:
        raise RuntimeError(
            f'unexpected verification result for {rootdir}: {result.success}'
        )


def main() -> int:
    os.makedirs(RESULTS_DIR, exist_ok=True)
    summary: dict[str, object] = {}
    with tempfile.TemporaryDirectory(dir=REPO_ROOT) as work:
        scenarios = {
            'small': (SMALL_FILES, SMALL_SIZE),
            'large': (LARGE_FILES, LARGE_SIZE),
        }
        for label, (count, size) in scenarios.items():
            store = os.path.join(work, label)
            summary[f'gen-{label}'] = profile_scenario(
                f'gen-{label}', lambda: generate(store, count, size)
            )
            summary[f'verify-clean-{label}'] = profile_scenario(
                f'verify-clean-{label}', lambda: verify(store, True)
            )
            corrupt_store = os.path.join(work, f'{label}-corrupt')
            shutil.copytree(store, corrupt_store)
            corrupt_some(corrupt_store)
            summary[f'verify-corrupt-{label}'] = profile_scenario(
                f'verify-corrupt-{label}',
                lambda: verify(corrupt_store, False),
            )

    out_path = os.path.join(RESULTS_DIR, 'profile-summary.json')
    with open(out_path, 'w') as f:
        json.dump(summary, f, indent=2)
        f.write('\n')
    print(f'Wrote {out_path}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
