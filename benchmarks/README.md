# Benchmarks

These scripts measure CAF generation and verification with stable dataset
shapes and measurement rules so results remain comparable across runs and
implementations.

## Scripts

- `bench.py`: end-to-end generation and verification benchmarks over the
  dataset matrix. Runs the installed `caf` entry point as a
  child process, measures each invocation with `os.wait4` (wall time,
  user/system CPU, peak RSS, 512-byte blocks read/written), and
  redirects all terminal output to per-dataset log files. Also probes
  raw sequential storage throughput to expose the storage ceiling.
  Results land in `results/<label>.json` with a full environment
  capture.

      uv run python benchmarks/bench.py --quick        # smoke
      uv run python benchmarks/bench.py                # full matrix
      uv run python benchmarks/bench.py --datasets files-100k-4k

- `profile_hotspots.py`: cProfile category breakdown (SHAKE, BLAKE2b,
  SHA3 header checksums, file I/O, fs metadata, store walk, corruption
  analysis, rich rendering) for generation, clean verification, and
  corrupted verification, at a small-file and a large-file scale.
  Writes `results/profile-*.txt` and `results/profile-summary.json`.

      uv run python benchmarks/profile_hotspots.py

## Measurement rules

- Warm-cache by default. Cold-cache runs require root (writing
  `/proc/sys/vm/drop_caches`) and are recorded separately when
  captured.
- Two warmup verification runs precede measured repetitions (one for
  datasets of at least 10 GiB); repetition counts are per-dataset in
  `bench.py` and scale down as dataset cost grows.
- Statistics reported: median, min, max, and median absolute
  deviation, plus files/s and MiB/s derived from wall time.
- Verification of corrupted stores must exit 1; the harness fails
  loudly on any unexpected exit status.
- Datasets are built under `benchmarks/.work/` (gitignored, same
  filesystem as the repo). Use `--work-dir` to target a different
  filesystem or device.
- Corruption is deterministic: a seeded sample of files gets a
  mid-content XOR-corrupted range, so corrupted-store runs are
  reproducible across implementations.

## Python-implementation notes

- The Python implementation is a single process with a single thread;
  there is no worker pool, so "best worker count" columns do not apply.
- `caf verify` output (including corruption reports) is rendered by
  rich; keeping it redirected is required for stable numbers.
