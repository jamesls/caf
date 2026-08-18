"""Benchmark CAF generation and verification.

Runs the Python implementation over a stable set of datasets. Terminal
output is redirected to log files so rendering cost does not affect
timing. Each measured
operation runs as a child process (the installed ``caf`` entry point)
and is measured with ``os.wait4``: wall time, user/system CPU time,
peak RSS, and 512-byte blocks read/written.

Results are written as JSON with a full environment capture so runs are
reproducible and comparable. Dataset shapes and measurement rules remain
stable across implementations.

Usage:
    uv run python benchmarks/bench.py --quick
    uv run python benchmarks/bench.py --datasets files-100k-4k
    uv run python benchmarks/bench.py            # full dataset matrix

Cold-cache runs require root (writing /proc/sys/vm/drop_caches) and
are skipped with a note when unavailable.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import random
import shutil
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass, field

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CAF_BIN = os.path.join(REPO_ROOT, '.venv', 'bin', 'caf')
RESULTS_DIR = os.path.join(REPO_ROOT, 'benchmarks', 'results')
DEFAULT_WORK_DIR = os.path.join(REPO_ROOT, 'benchmarks', '.work')

CORRUPT_SEED = 0x5CAF
RAW_IO_BYTES = 4 * 1024**3
RAW_IO_BUFFER = 1024 * 1024


@dataclass
class DatasetSpec:
    """One benchmark dataset."""

    name: str
    purpose: str
    gen_args: list[str]
    gen_reps: int
    verify_reps: int
    verify_warmups: int
    corrupt_files: int
    corrupt_length: int = 4096


DATASETS: list[DatasetSpec] = [
    DatasetSpec(
        name='files-1k-4k',
        purpose='Quick smoke dataset',
        gen_args=['--max-files', '1000', '--file-size', '4096'],
        gen_reps=3,
        verify_reps=5,
        verify_warmups=2,
        corrupt_files=5,
    ),
    DatasetSpec(
        name='files-100k-4k',
        purpose='Directory and per-file overhead',
        gen_args=['--max-files', '100000', '--file-size', '4096'],
        gen_reps=3,
        verify_reps=5,
        verify_warmups=2,
        corrupt_files=100,
    ),
    DatasetSpec(
        name='files-10k-64k',
        purpose='Mixed metadata and content cost',
        gen_args=['--max-files', '10000', '--file-size', '64kb'],
        gen_reps=3,
        verify_reps=5,
        verify_warmups=2,
        corrupt_files=20,
    ),
    DatasetSpec(
        name='files-1k-1m',
        purpose='Hash and SHAKE throughput',
        gen_args=['--max-files', '1000', '--file-size', '1mb'],
        gen_reps=3,
        verify_reps=5,
        verify_warmups=2,
        corrupt_files=10,
    ),
    DatasetSpec(
        name='files-10-1g',
        purpose='Sequential byte throughput',
        gen_args=['--max-files', '10', '--file-size', '1gb'],
        gen_reps=2,
        verify_reps=3,
        verify_warmups=1,
        corrupt_files=2,
    ),
    DatasetSpec(
        name='mixed-lognormal-10g',
        purpose='Real CLI size selection (lognormal to 10 GiB)',
        gen_args=[
            '--max-disk-usage',
            '10GB',
            '--file-size',
            'Type=lognormal,Mean=14,StdDev=1',
        ],
        gen_reps=2,
        verify_reps=3,
        verify_warmups=1,
        corrupt_files=10,
    ),
]

QUICK_DATASETS = ['files-1k-4k']
FULL_DATASETS = [d.name for d in DATASETS if d.name != 'files-1k-4k']


@dataclass
class RunMetrics:
    """Measurements for one child-process invocation."""

    wall_s: float
    cpu_user_s: float
    cpu_sys_s: float
    max_rss_kib: int
    blocks_read: int
    blocks_written: int
    exit_code: int

    def as_dict(self) -> dict[str, float | int]:
        return {
            'wall_s': round(self.wall_s, 4),
            'cpu_user_s': round(self.cpu_user_s, 4),
            'cpu_sys_s': round(self.cpu_sys_s, 4),
            'max_rss_kib': self.max_rss_kib,
            'blocks_read': self.blocks_read,
            'blocks_written': self.blocks_written,
            'exit_code': self.exit_code,
        }


@dataclass
class DatasetState:
    """Filesystem locations for a prepared dataset."""

    spec: DatasetSpec
    data_dir: str
    corrupt_dir: str
    file_count: int = 0
    total_bytes: int = 0
    results: dict[str, object] = field(default_factory=dict)


def run_measured(argv: list[str], log_path: str) -> RunMetrics:
    """Run a child process, appending output to ``log_path``."""
    with open(log_path, 'ab') as log:
        file_actions = [
            (os.POSIX_SPAWN_DUP2, log.fileno(), 1),
            (os.POSIX_SPAWN_DUP2, log.fileno(), 2),
        ]
        start = time.monotonic()
        pid = os.posix_spawn(
            argv[0], argv, dict(os.environ), file_actions=file_actions
        )
        _, status, rusage = os.wait4(pid, 0)
        wall_s = time.monotonic() - start
    return RunMetrics(
        wall_s=wall_s,
        cpu_user_s=rusage.ru_utime,
        cpu_sys_s=rusage.ru_stime,
        max_rss_kib=rusage.ru_maxrss,
        blocks_read=rusage.ru_inblock,
        blocks_written=rusage.ru_oublock,
        exit_code=os.waitstatus_to_exitcode(status),
    )


def data_files(rootdir: str) -> list[str]:
    found = []
    for root, dirnames, filenames in os.walk(rootdir):
        dirnames[:] = [d for d in dirnames if d != '.metadata']
        for filename in filenames:
            found.append(os.path.join(root, filename))
    return sorted(found)


def summarize(values: list[float]) -> dict[str, float]:
    med = statistics.median(values)
    mad = statistics.median([abs(v - med) for v in values])
    return {
        'n': len(values),
        'median': round(med, 4),
        'min': round(min(values), 4),
        'max': round(max(values), 4),
        'mad': round(mad, 4),
    }


def op_summary(
    reps: list[RunMetrics], file_count: int, total_bytes: int
) -> dict[str, object]:
    walls = [m.wall_s for m in reps]
    return {
        'reps': [m.as_dict() for m in reps],
        'wall_s': summarize(walls),
        'files_per_s': summarize([file_count / w for w in walls]),
        'mib_per_s': summarize([total_bytes / w / 1024**2 for w in walls]),
        'max_rss_kib': max(m.max_rss_kib for m in reps),
    }


def read_first_line(path: str) -> str:
    try:
        with open(path) as f:
            return f.readline().strip()
    except OSError:
        return 'unknown'


def command_output(argv: list[str]) -> str:
    try:
        return subprocess.run(
            argv, capture_output=True, text=True, check=False
        ).stdout.strip()
    except OSError:
        return 'unknown'


def capture_environment(work_dir: str) -> dict[str, object]:
    cpu_model = 'unknown'
    with open('/proc/cpuinfo') as f:
        for line in f:
            if line.startswith('model name'):
                cpu_model = line.split(':', 1)[1].strip()
                break
    os_release = 'unknown'
    with open('/etc/os-release') as f:
        for line in f:
            if line.startswith('PRETTY_NAME='):
                os_release = line.split('=', 1)[1].strip().strip('"')
                break
    return {
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S%z'),
        'os': os_release,
        'kernel': platform.release(),
        'cpu': cpu_model,
        'cpu_count': os.cpu_count(),
        'mem_total': read_first_line('/proc/meminfo'),
        'python': sys.version.split()[0],
        'caf_version': command_output([CAF_BIN, '--version']),
        'caf_commit': command_output([
            'git',
            '-C',
            REPO_ROOT,
            'rev-parse',
            '--short',
            'HEAD',
        ]),
        'git_dirty': bool(
            command_output(['git', '-C', REPO_ROOT, 'status', '--porcelain'])
        ),
        'work_dir': work_dir,
        'filesystem': command_output(['stat', '-f', '-c', '%T', work_dir]),
        'mount_source': command_output([
            'findmnt',
            '-n',
            '-o',
            'SOURCE',
            '--target',
            work_dir,
        ]),
        'process_model': 'single process, single thread (no worker pool '
        'exists in the Python implementation)',
    }


def measure_raw_sequential_io(work_dir: str) -> dict[str, object]:
    """Raw sequential write/read throughput of the work filesystem.

    Shows when storage, rather than CAF, limits improvement. The read
    pass is warm-cache unless the file exceeds RAM.
    """
    path = os.path.join(work_dir, 'raw-io-probe.bin')
    buffer = os.urandom(RAW_IO_BUFFER)
    start = time.monotonic()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    try:
        written = 0
        while written < RAW_IO_BYTES:
            os.write(fd, buffer)
            written += len(buffer)
        os.fdatasync(fd)
    finally:
        os.close(fd)
    write_s = time.monotonic() - start

    start = time.monotonic()
    read = 0
    with open(path, 'rb', buffering=0) as f:
        while chunk := f.read(RAW_IO_BUFFER):
            read += len(chunk)
    read_s = time.monotonic() - start
    os.remove(path)
    return {
        'bytes': RAW_IO_BYTES,
        'write_mib_per_s': round(RAW_IO_BYTES / write_s / 1024**2, 1),
        'warm_read_mib_per_s': round(read / read_s / 1024**2, 1),
    }


def corrupt_dataset(state: DatasetState) -> None:
    """Copy the dataset and corrupt a deterministic sample of files."""
    if os.path.isdir(state.corrupt_dir):
        shutil.rmtree(state.corrupt_dir)
    shutil.copytree(state.data_dir, state.corrupt_dir)
    files = data_files(state.corrupt_dir)
    rng = random.Random(CORRUPT_SEED)
    count = min(state.spec.corrupt_files, len(files))
    for path in rng.sample(files, count):
        size = os.path.getsize(path)
        length = min(state.spec.corrupt_length, max(1, size - 60))
        offset = 60 + max(0, (size - 60 - length) // 2)
        with open(path, 'r+b') as f:
            f.seek(offset)
            original = f.read(length)
            f.seek(offset)
            f.write(bytes(b ^ 0xFF for b in original))


def bench_generation(state: DatasetState, log_path: str) -> None:
    spec = state.spec
    reps: list[RunMetrics] = []
    for rep in range(spec.gen_reps):
        rep_dir = f'{state.data_dir}.rep{rep}'
        if os.path.isdir(rep_dir):
            shutil.rmtree(rep_dir)
        argv = [CAF_BIN, 'gen', '--directory', rep_dir, *spec.gen_args]
        metrics = run_measured(argv, log_path)
        if metrics.exit_code != 0:
            raise RuntimeError(
                f'gen failed for {spec.name} (rep {rep}), see {log_path}'
            )
        reps.append(metrics)
        files = data_files(rep_dir)
        state.file_count = len(files)
        state.total_bytes = sum(os.path.getsize(p) for p in files)
        if os.path.isdir(state.data_dir):
            shutil.rmtree(state.data_dir)
        os.rename(rep_dir, state.data_dir)
        print(
            f'  gen rep {rep}: {metrics.wall_s:.2f}s '
            f'({state.file_count / metrics.wall_s:.0f} files/s)'
        )
    state.results['gen'] = op_summary(
        reps, state.file_count, state.total_bytes
    )


def bench_verification(
    state: DatasetState,
    log_path: str,
    directory: str,
    label: str,
    expect_exit: int,
) -> None:
    spec = state.spec
    argv = [CAF_BIN, 'verify', '--directory', directory]
    for _ in range(spec.verify_warmups):
        run_measured(argv, log_path)
    reps: list[RunMetrics] = []
    for rep in range(spec.verify_reps):
        metrics = run_measured(argv, log_path)
        if metrics.exit_code != expect_exit:
            raise RuntimeError(
                f'verify ({label}) for {spec.name} exited '
                f'{metrics.exit_code}, expected {expect_exit}; '
                f'see {log_path}'
            )
        reps.append(metrics)
        print(
            f'  {label} rep {rep}: {metrics.wall_s:.2f}s '
            f'({state.file_count / metrics.wall_s:.0f} files/s)'
        )
    state.results[label] = op_summary(
        reps, state.file_count, state.total_bytes
    )


def bench_dataset(
    spec: DatasetSpec, work_dir: str, keep: bool
) -> dict[str, object]:
    print(f'=== {spec.name}: {spec.purpose}')
    dataset_root = os.path.join(work_dir, spec.name)
    os.makedirs(dataset_root, exist_ok=True)
    log_path = os.path.join(dataset_root, 'output.log')
    state = DatasetState(
        spec=spec,
        data_dir=os.path.join(dataset_root, 'data'),
        corrupt_dir=os.path.join(dataset_root, 'data-corrupt'),
    )
    bench_generation(state, log_path)
    bench_verification(state, log_path, state.data_dir, 'verify_clean_warm', 0)
    corrupt_dataset(state)
    bench_verification(
        state, log_path, state.corrupt_dir, 'verify_corrupt_warm', 1
    )
    if not keep:
        shutil.rmtree(state.data_dir, ignore_errors=True)
        shutil.rmtree(state.corrupt_dir, ignore_errors=True)
    return {
        'purpose': spec.purpose,
        'gen_args': spec.gen_args,
        'file_count': state.file_count,
        'total_bytes': state.total_bytes,
        'corrupted_files': min(spec.corrupt_files, state.file_count),
        'verify_warmups': spec.verify_warmups,
        **state.results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        '--datasets',
        nargs='+',
        choices=[d.name for d in DATASETS],
        help='Datasets to run (default: the full dataset matrix).',
    )
    parser.add_argument(
        '--quick',
        action='store_true',
        help='Run only the small smoke dataset.',
    )
    parser.add_argument('--label', default='baseline')
    parser.add_argument('--work-dir', default=DEFAULT_WORK_DIR)
    parser.add_argument(
        '--keep',
        action='store_true',
        help='Keep generated datasets after the run.',
    )
    parser.add_argument(
        '--skip-raw-io',
        action='store_true',
        help='Skip the raw sequential storage probe.',
    )
    args = parser.parse_args()

    if not os.path.exists(CAF_BIN):
        print(f'{CAF_BIN} not found; run `uv sync` first', file=sys.stderr)
        return 1

    if args.datasets:
        selected = args.datasets
    elif args.quick:
        selected = QUICK_DATASETS
    else:
        selected = FULL_DATASETS
    specs = [d for d in DATASETS if d.name in selected]

    work_dir = os.path.abspath(args.work_dir)
    os.makedirs(work_dir, exist_ok=True)
    os.makedirs(RESULTS_DIR, exist_ok=True)

    datasets: dict[str, object] = {}
    results: dict[str, object] = {
        'environment': capture_environment(work_dir),
        'measurement_rules': {
            'child_measurement': 'os.wait4 rusage per caf invocation',
            'terminal_output': 'redirected to per-dataset output.log',
            'cache_state': 'warm (cold runs require root; not captured)',
            'block_size_note': 'blocks_read/written are 512-byte units',
        },
        'datasets': datasets,
    }
    if not args.skip_raw_io:
        print('=== raw sequential storage probe')
        results['raw_sequential_io'] = measure_raw_sequential_io(work_dir)
        print(f'  {results["raw_sequential_io"]}')

    out_path = os.path.join(RESULTS_DIR, f'{args.label}.json')
    for spec in specs:
        datasets[spec.name] = bench_dataset(spec, work_dir, args.keep)
        with open(out_path, 'w') as f:
            json.dump(results, f, indent=2)
            f.write('\n')
    print(f'Wrote {out_path}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
