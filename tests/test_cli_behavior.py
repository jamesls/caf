import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from click.testing import CliRunner, Result

from caf.cli import main
from caf.constants import HEADER_SIZE, ROOT_PARENT_HASH


def data_files(rootdir: str | os.PathLike[str]) -> Iterator[str]:
    for root, _, filenames in os.walk(rootdir):
        if '.metadata' in root:
            continue
        for filename in filenames:
            yield os.path.join(root, filename)


def gen(tmp_path: Path, *args: str) -> Result:
    runner = CliRunner()
    return runner.invoke(main, ['gen', '--directory', str(tmp_path), *args])


def verify(tmp_path: Path, *args: str) -> Result:
    runner = CliRunner()
    return runner.invoke(main, ['verify', '--directory', str(tmp_path), *args])


def test_version_reporting() -> None:
    result = CliRunner().invoke(main, ['--version'])
    assert result.exit_code == 0
    assert result.output.startswith('caf, version ')


def test_unknown_command_is_usage_error() -> None:
    result = CliRunner().invoke(main, ['not-a-command'])
    assert result.exit_code == 2


def test_invalid_file_size_spec_is_usage_error(tmp_path: Path) -> None:
    assert gen(tmp_path, '--file-size', 'bogus').exit_code == 2


def test_invalid_range_spec_is_usage_error(tmp_path: Path) -> None:
    assert gen(tmp_path, '--file-size', '1mb-2mb-3mb').exit_code == 2


def test_shorthand_missing_type_is_usage_error(tmp_path: Path) -> None:
    assert gen(tmp_path, '--file-size', 'Mean=1,StdDev=1').exit_code == 2


def test_shorthand_unknown_type_is_usage_error(tmp_path: Path) -> None:
    result = gen(tmp_path, '--file-size', 'Type=zipf,Mean=1')
    assert result.exit_code == 2


def test_invalid_max_disk_usage_is_usage_error(tmp_path: Path) -> None:
    assert gen(tmp_path, '--max-disk-usage', '1xy').exit_code == 2


def test_gen_default_is_100_files_of_4096_bytes(tmp_path: Path) -> None:
    assert gen(tmp_path).exit_code == 0
    sizes = [os.path.getsize(p) for p in data_files(tmp_path)]
    assert len(sizes) == 100
    assert all(size == 4096 for size in sizes)


@pytest.mark.parametrize(
    'spec,expected',
    [
        ('8192', 8192),
        ('2kb', 2 * 1024),
        ('2KB', 2 * 1024),
        ('2Kb', 2 * 1024),
        ('1mb', 1024 * 1024),
        ('1MB', 1024 * 1024),
    ],
)
def test_file_size_suffix_grammar(
    tmp_path: Path, spec: str, expected: int
) -> None:
    result = gen(tmp_path, '--max-files', '1', '--file-size', spec)
    assert result.exit_code == 0, result.output
    assert [os.path.getsize(p) for p in data_files(tmp_path)] == [expected]


@pytest.mark.parametrize('suffix', ['gb', 'tb'])
def test_max_disk_usage_large_suffixes_parse(
    tmp_path: Path, suffix: str
) -> None:
    # One small file exercises gb/tb parsing without reaching the budget
    # or consuming large amounts of disk space.
    result = gen(
        tmp_path,
        '--max-files',
        '1',
        '--file-size',
        '60',
        '--max-disk-usage',
        f'1{suffix}',
    )
    assert result.exit_code == 0, result.output
    assert len(list(data_files(tmp_path))) == 1


def test_file_size_range_is_inclusive(tmp_path: Path) -> None:
    # A degenerate range has the same 60-byte value at both endpoints.
    result = gen(tmp_path, '--max-files', '3', '--file-size', '60-60')
    assert result.exit_code == 0, result.output
    sizes = [os.path.getsize(p) for p in data_files(tmp_path)]
    assert sizes == [60, 60, 60]


def test_file_size_below_header_is_clamped_to_60(tmp_path: Path) -> None:
    result = gen(tmp_path, '--max-files', '1', '--file-size', '0')
    assert result.exit_code == 0, result.output
    sizes = [os.path.getsize(p) for p in data_files(tmp_path)]
    assert sizes == [HEADER_SIZE]


def test_normal_distribution_grammar(tmp_path: Path) -> None:
    # StdDev=0 makes every sample equal Mean.
    result = gen(
        tmp_path,
        '--max-files',
        '2',
        '--file-size',
        'Type=normal,Mean=1kb,StdDev=0',
    )
    assert result.exit_code == 0, result.output
    sizes = [os.path.getsize(p) for p in data_files(tmp_path)]
    assert sizes == [1024, 1024]


def test_lognormal_distribution_grammar_log_space(tmp_path: Path) -> None:
    # Lognormal parameters use log space. Mean=8 with StdDev=0 yields
    # int(e^8) and truncates to 2980 bytes rather than 8 bytes.
    result = gen(
        tmp_path,
        '--max-files',
        '1',
        '--file-size',
        'Type=lognormal,Mean=8,StdDev=0',
    )
    assert result.exit_code == 0, result.output
    sizes = [os.path.getsize(p) for p in data_files(tmp_path)]
    assert sizes == [2980]


def test_gamma_distribution_grammar(tmp_path: Path) -> None:
    result = gen(
        tmp_path,
        '--max-files',
        '2',
        '--file-size',
        'Type=gamma,Alpha=2,Beta=1kb',
    )
    assert result.exit_code == 0, result.output
    sizes = [os.path.getsize(p) for p in data_files(tmp_path)]
    assert len(sizes) == 2
    assert all(size >= HEADER_SIZE for size in sizes)


def test_max_disk_usage_checked_before_each_file(tmp_path: Path) -> None:
    # The budget check runs before each file. A 10000-byte budget allows
    # three 4096-byte files and stops at 12288 bytes.
    result = gen(tmp_path, '--max-disk-usage', '10000', '--file-size', '4096')
    assert result.exit_code == 0, result.output
    sizes = [os.path.getsize(p) for p in data_files(tmp_path)]
    assert len(sizes) == 3
    assert sum(sizes) == 12288


def test_gen_zero_files_writes_zero_chain_tip(tmp_path: Path) -> None:
    result = gen(tmp_path, '--max-files', '0')
    assert result.exit_code == 0, result.output
    assert list(data_files(tmp_path)) == []
    roots = os.listdir(tmp_path / '.metadata' / 'roots')
    assert roots == [ROOT_PARENT_HASH.hex()]
    assert verify(tmp_path).exit_code == 0


def test_gen_creates_missing_directory(tmp_path: Path) -> None:
    target = tmp_path / 'nested' / 'store'
    result = gen(target, '--max-files', '1')
    assert result.exit_code == 0, result.output
    assert len(list(data_files(target))) == 1


def test_verify_non_store_directory_fails(tmp_path: Path) -> None:
    result = verify(tmp_path)
    assert result.exit_code == 1
    # Normalize whitespace because rich can wrap long messages across
    # terminal lines.
    assert 'not a valid CAF store' in ' '.join(result.output.split())


def test_verify_reports_analysis_chunk_size(tmp_path: Path) -> None:
    assert gen(tmp_path, '--max-files', '1').exit_code == 0
    result = verify(tmp_path, '--chunk-size', '512')
    assert result.exit_code == 0
    assert '512 bytes' in result.output


def test_dev_show_missing_file_is_usage_error() -> None:
    result = CliRunner().invoke(main, ['dev', 'show', '/nonexistent'])
    assert result.exit_code == 2


def test_dev_corrupt_file_start_beyond_eof_is_usage_error(
    tmp_path: Path,
) -> None:
    assert gen(tmp_path, '--max-files', '1').exit_code == 0
    target = next(iter(data_files(tmp_path)))
    result = CliRunner().invoke(
        main, ['dev', 'corrupt-file', target, '--start', '99999']
    )
    assert result.exit_code == 2


def test_dev_corrupt_file_zero_preset_breaks_verification(
    tmp_path: Path,
) -> None:
    assert gen(tmp_path, '--max-files', '1').exit_code == 0
    target = next(iter(data_files(tmp_path)))
    result = CliRunner().invoke(
        main,
        [
            'dev',
            'corrupt-file',
            target,
            '--preset',
            'zero',
            '--start',
            '100',
            '--length',
            '100',
        ],
    )
    assert result.exit_code == 0, result.output
    assert verify(tmp_path).exit_code == 1


def test_dev_corrupt_file_random_seed_is_reproducible(
    tmp_path: Path,
) -> None:
    assert gen(tmp_path, '--max-files', '1').exit_code == 0
    target = next(iter(data_files(tmp_path)))
    with open(target, 'rb') as f:
        original = f.read()

    def corrupt_and_read() -> bytes:
        with open(target, 'wb') as f:
            f.write(original)
        result = CliRunner().invoke(
            main,
            [
                'dev',
                'corrupt-file',
                target,
                '--preset',
                'random',
                '--seed',
                '42',
                '--start',
                '100',
                '--length',
                '64',
            ],
        )
        assert result.exit_code == 0, result.output
        with open(target, 'rb') as f:
            return f.read()

    assert corrupt_and_read() == corrupt_and_read()
