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


def test_verify_with_directory_option(tmp_path):
    runner = CliRunner()

    result = runner.invoke(
        main,
        [
            'gen',
            '--directory',
            str(tmp_path),
            '--max-files',
            '2',
            '--file-size',
            '1024',
        ],
    )
    assert result.exit_code == 0

    result = runner.invoke(main, ['verify', '--directory', str(tmp_path)])
    assert result.exit_code == 0
    assert 'successfully verified' in result.output


def test_verify_detects_corruption(tmp_path):
    runner = CliRunner()

    result = runner.invoke(
        main,
        [
            'gen',
            '--directory',
            str(tmp_path),
            '--max-files',
            '1',
            '--file-size',
            '2048',
        ],
    )
    assert result.exit_code == 0

    for root, _, files in os.walk(tmp_path):
        if '.metadata' in root:
            continue
        if files:
            file_path = os.path.join(root, files[0])
            with open(file_path, 'r+b') as f:
                f.seek(200)
                f.write(b'\xff' * 1000)
            break

    result = runner.invoke(main, ['verify', '--directory', str(tmp_path)])
    assert result.exit_code == 1
    assert 'CORRUPTION' in result.output


def test_verify_chunk_size_option(tmp_path):
    runner = CliRunner()

    result = runner.invoke(
        main,
        [
            'gen',
            '--directory',
            str(tmp_path),
            '--max-files',
            '1',
            '--file-size',
            '2048',
        ],
    )
    assert result.exit_code == 0

    for chunk_size in [256, 1024, 2048]:
        result = runner.invoke(
            main,
            [
                'verify',
                '--directory',
                str(tmp_path),
                '--chunk-size',
                str(chunk_size),
            ],
        )
        assert result.exit_code == 0
        assert f'{chunk_size:,} bytes' in result.output
