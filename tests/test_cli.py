import os
import random
from typing import Iterable

from click.testing import CliRunner
from caf.cli import main


def get_all_generated_files(rootdir: str) -> Iterable[str]:
    for root, _, filenames in os.walk(rootdir):
        if '.metadata' in root:
            continue
        for filename in filenames:
            yield os.path.join(root, filename)


def run_gen(runner: CliRunner, tmpdir: str, *args: str):
    return runner.invoke(main, ['gen', '--directory', tmpdir, *args])


def run_verify(runner: CliRunner, tmpdir: str):
    cwd = os.getcwd()
    os.chdir(tmpdir)
    try:
        return runner.invoke(main, ['verify'])
    finally:
        os.chdir(cwd)


def test_default_file_count(tmp_path):
    runner = CliRunner()
    result = run_gen(runner, str(tmp_path))
    assert result.exit_code == 0, result.output
    files = list(get_all_generated_files(tmp_path))
    assert len(files) == 100


def test_specify_file_size_bytes(tmp_path):
    runner = CliRunner()
    result = run_gen(
        runner,
        str(tmp_path),
        '--max-files',
        '5',
        '--file-size',
        '4096',
    )
    assert result.exit_code == 0, result.output
    for path in get_all_generated_files(tmp_path):
        assert os.path.getsize(path) == 4096


def test_specify_file_size_kb(tmp_path):
    runner = CliRunner()
    result = run_gen(
        runner,
        str(tmp_path),
        '--max-files',
        '5',
        '--file-size',
        '16kb',
    )
    assert result.exit_code == 0, result.output
    for path in get_all_generated_files(tmp_path):
        assert os.path.getsize(path) == 16 * 1024


def test_specify_file_size_mb(tmp_path):
    runner = CliRunner()
    result = run_gen(
        runner,
        str(tmp_path),
        '--file-size',
        '1MB',
        '--max-files',
        '5',
    )
    assert result.exit_code == 0, result.output
    for path in get_all_generated_files(tmp_path):
        assert os.path.getsize(path) == 1 * 1024 * 1024


def test_specify_file_size_range(tmp_path):
    runner = CliRunner()
    result = run_gen(
        runner,
        str(tmp_path),
        '--file-size',
        '4048-8096',
        '--max-files',
        '5',
    )
    assert result.exit_code == 0, result.output
    for path in get_all_generated_files(tmp_path):
        size = os.path.getsize(path)
        assert 4048 <= size <= 8096


def test_max_disk_usage_bytes(tmp_path):
    runner = CliRunner()
    result = run_gen(
        runner,
        str(tmp_path),
        '--max-disk-usage',
        '16384',
    )
    assert result.exit_code == 0, result.output
    total_size = sum(
        os.path.getsize(p) for p in get_all_generated_files(tmp_path)
    )
    assert total_size == 16384


def test_max_disk_usage_mb(tmp_path):
    runner = CliRunner()
    result = run_gen(
        runner,
        str(tmp_path),
        '--max-disk-usage',
        '1MB',
    )
    assert result.exit_code == 0, result.output
    total_size = sum(
        os.path.getsize(p) for p in get_all_generated_files(tmp_path)
    )
    assert total_size == 1 * 1024 * 1024


def test_max_disk_usage_and_file_count(tmp_path):
    runner = CliRunner()
    result = run_gen(
        runner,
        str(tmp_path),
        '--max-disk-usage',
        '16384',
        '--max-files',
        '2',
    )
    assert result.exit_code == 0, result.output
    files = list(get_all_generated_files(tmp_path))
    assert len(files) == 2


def test_verify_success(tmp_path):
    runner = CliRunner()
    result = run_gen(runner, str(tmp_path))
    assert result.exit_code == 0, result.output
    verify_result = run_verify(runner, str(tmp_path))
    assert verify_result.exit_code == 0, verify_result.output


def test_verify_failure(tmp_path):
    runner = CliRunner()
    result = run_gen(runner, str(tmp_path))
    assert result.exit_code == 0, result.output
    files = list(get_all_generated_files(tmp_path))
    os.remove(random.choice(files))
    verify_result = run_verify(runner, str(tmp_path))
    assert verify_result.exit_code == 1
