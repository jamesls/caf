import os
import random
import functools
import hashlib
import struct
from dataclasses import dataclass
from typing import Callable, Optional
from importlib.metadata import version

import click
from rich.console import Console
from rich.text import Text

from caf.constants import BLOCK_SIZE, HEADER_SIZE, ROOT_PARENT_HASH
from caf.generator import FileGenerator
from caf.paths import hash_to_path, parse_hash_from_path
from caf.verifier import FileVerifier


__version__ = version("caf")


SIZE_TYPES = {
    'kb': 1024,
    'mb': 1024**2,
    'gb': 1024**3,
    'tb': 1024**4,
}


def current_directory(
    ctx: click.Context, param: click.Parameter, value: Optional[str]
) -> str:
    if value is None:
        return os.getcwd()
    else:
        return value


def convert_to_bytes(
    ctx: click.Context, param: click.Parameter, value: Optional[str]
) -> Optional[int]:
    if value is None:
        return None
    is_size_identifier = len(value) >= 2 and value[-2:].lower() in SIZE_TYPES
    if not is_size_identifier:
        try:
            return int(value)
        except ValueError:
            raise click.BadParameter("Invalid size specifier")
    else:
        multiplier = SIZE_TYPES[value[-2:].lower()]
        return int(value[:-2]) * multiplier


def identity(value: int) -> Callable[[], int]:
    return lambda: value


class FileSizeType(click.ParamType):
    # ``name`` is used by the --help output.
    name = 'filesize'

    RANDOM_FUNCTION = {
        'normal': lambda Mean, StdDev: abs(int(random.gauss(Mean, StdDev))),
        'gamma': lambda Alpha, Beta: abs(
            int(random.gammavariate(Alpha, Beta))
        ),
        'lognormal': lambda Mean, StdDev: abs(
            int(random.lognormvariate(Mean, StdDev))
        ),
    }

    def convert(
        self,
        value: str,
        param: click.Parameter | None,
        ctx: click.Context | None,
    ) -> Callable[[], int]:
        try:
            v = int(value)
            return identity(v)
        except ValueError:
            pass
        if ',' in value:
            return self._parse_shorthand(value)
        elif '-' in value:
            parts = value.split('-')
            if not len(parts) == 2:
                self.fail(
                    'Bad value for --filesize: %s\n\nShould be '
                    'startsize-endsize (e.g. 1mb-5mb).' % value
                )
            start = self._parse_with_size_suffix(parts[0])
            end = self._parse_with_size_suffix(parts[1])
            return lambda: random.randint(start, end)
        elif self._is_size_identifier(value):
            return identity(self._parse_with_size_suffix(value))
        else:
            self.fail('Unknown size specifier "%s"' % value, param, ctx)

    def _is_size_identifier(self, value: str) -> bool:
        return len(value) >= 2 and value[-2:].lower() in SIZE_TYPES

    def _parse_with_size_suffix(self, value: str) -> int:
        if self._is_size_identifier(value):
            multiplier = SIZE_TYPES[value[-2:].lower()]
            return int(value[:-2]) * multiplier
        else:
            return int(value)

    def _parse_shorthand(self, value: str) -> Callable[[], int]:
        # Shorthand is of the form
        # A=1,B=3,C=3
        shorthand_dict = {}
        for item in value.split(','):
            k, v = item.split('=')
            shorthand_dict[k] = v
        if 'Type' not in shorthand_dict:
            self.fail("Missing Type=<type> in file size specifier: %s" % value)
        param_type = shorthand_dict.pop('Type')
        if param_type not in self.RANDOM_FUNCTION:
            self.fail(
                "Unknown Type '%s', must be one of: %s"
                % (param_type, ','.join(self.RANDOM_FUNCTION))
            )
        for key, value in shorthand_dict.items():
            shorthand_dict[key] = self._parse_with_size_suffix(value)
        func = functools.partial(
            self.RANDOM_FUNCTION[param_type], **shorthand_dict
        )
        return func


@click.group()
@click.version_option(version=__version__, prog_name='caf')
def main():
    pass


@main.command()
@click.option(
    '--directory',
    help='The directory where files will be generated.',
    callback=current_directory,
)
@click.option(
    '--max-files', type=int, help='The maximum number of files to generate.'
)
@click.option(
    '--max-disk-usage',
    callback=convert_to_bytes,
    help='The maximum disk space to use when generating files.',
)
@click.option(
    '--file-size',
    default=4096,
    type=FileSizeType(),
    help='The size of the files that are generated.  '
    'Value is either in bytes or can be suffixed with '
    'kb, mb, gb, etc.  Suffix is case insensitive (we '
    'know what you mean).',
)
def gen(
    directory: str,
    max_files: float | None,
    max_disk_usage: float | None,
    file_size: Callable[[], int],
) -> None:
    """Generate content addressable files.

    This command will generate a set of linked, content addressable files.

    The default behavior is to generate 100 files in the current directory.
    Each file will be a fixed size of 4048 bytes:

        \b
        caf gen

    You can specify the directory where the files should be generated,
    the maximum number of files to generate, and indicate that each file
    should be of an exact size:

        \b
        caf gen --directory /tmp/files --max-files 1000 --file-size 4KB

    The -m/--max-files is one of two stopping conditions.  A stopping
    condition is what indicates when this command should stop generating
    files.  The other stopping condition is "-u/--max-disk-usage".  Either
    stopping condition can be used.  If both stopping conditions are specified,
    then this command will stop generating files as soon as any stopping
    condition is met.

    For example, this command will generate files until either 10000 files
    are generated, or we've used 100MB of space:

        \b
        caf gen -d /tmp/files --max-files 10000 --max-disk-usage 100MB

    Now, in the above example the "--max-disk-usage" is actually unnecessary
    because we know that 10000 files at a file size of 4KB is going to be
    around 38.6MB.  Given we can calculate the amount of disk usage,
    when would --max-disk-usage ever be useful?

    The answer is when we don't have a fixed file size.  This command
    gives you several options for specifying a range of file sizes that
    can be randomly chosen.  For example, we could generate files that
    have a random size between 4048KB and 10MB:

        caf gen --file-size 4048KB-10MB

    Instead of specifying a range of file sizes, you can also specify
    a random distribution that the file sizes should follow.  For
    example, if you want to generate files that follow a normal (Gaussian)
    distribution, you can specify the mean and the standard deviation
    by using:

        caf gen --file-size Type=normal,Mean=20MB,StdDev=1MB

    You can also a gamma distribution:

        caf gen --file-size Type=gamma,Alpha=20MB,Beta=1MB

    And finally a lognormal distribution:

        caf gen --file-size Type=lognormal,Mean=10MB,StdDev=1MB

    """
    if max_files is None and max_disk_usage is not None:
        max_files = float('inf')
    elif max_files is not None and max_disk_usage is None:
        max_disk_usage = float('inf')
    elif max_files is None and max_disk_usage is None:
        # The default no args specified is to generate
        # 100 files.
        max_files = 100
        max_disk_usage = float('inf')
    # "file_size" is actually a no-arg function created by
    # FileSizeType.  Is there a way in click to specify the destination?
    file_size_chooser = file_size
    os.makedirs(directory, exist_ok=True)
    generator = FileGenerator(
        directory, max_files, max_disk_usage, file_size_chooser
    )
    generator.generate_files()


@main.group()
def dev():
    """Development tools for testing caf."""
    pass


def _yes_no(value: bool) -> str:
    if value:
        return '[green]yes[/]'
    return '[red]no[/]'


@dataclass(frozen=True)
class CafHeaderDiagnostics:
    parent_hash: bytes
    content_seed: bytes
    file_length: int
    stored_header_checksum: bytes
    calculated_header_checksum: bytes
    reserved: bytes
    actual_size: int

    @property
    def header_checksum_valid(self) -> bool:
        return self.stored_header_checksum == self.calculated_header_checksum

    @property
    def reserved_valid(self) -> bool:
        return self.reserved == (b'\x00' * 8)

    @property
    def file_length_matches(self) -> bool:
        return self.file_length == self.actual_size

    @property
    def file_length_minimum(self) -> bool:
        return self.file_length >= HEADER_SIZE

    @property
    def root_file(self) -> bool:
        return self.parent_hash == ROOT_PARENT_HASH

    @property
    def basic_valid(self) -> bool:
        return (
            self.header_checksum_valid
            and self.reserved_valid
            and self.file_length_matches
            and self.file_length_minimum
        )


def _load_caf_header_diagnostics(filepath: str) -> CafHeaderDiagnostics:
    actual_size = os.path.getsize(filepath)
    with open(filepath, 'rb') as f:
        header = f.read(HEADER_SIZE)

    if len(header) < HEADER_SIZE:
        raise click.ClickException(
            f'File is too small to be a CAF file: expected at least '
            f'{HEADER_SIZE} bytes, got {len(header)}.'
        )

    parent_hash = header[0:20]
    content_seed = header[20:36]
    file_length = struct.unpack('>Q', header[36:44])[0]
    stored_header_checksum = header[44:52]
    calculated_header_checksum = hashlib.sha3_256(header[:44]).digest()[:8]
    reserved = header[52:60]

    return CafHeaderDiagnostics(
        parent_hash=parent_hash,
        content_seed=content_seed,
        file_length=file_length,
        stored_header_checksum=stored_header_checksum,
        calculated_header_checksum=calculated_header_checksum,
        reserved=reserved,
        actual_size=actual_size,
    )


def _print_caf_header_diagnostics(
    console: Console,
    filepath: str,
    diag: CafHeaderDiagnostics,
    expected_hash: str,
) -> None:
    console.print('[bold]File:[/]', Text(filepath))
    console.print(
        f'[bold]Actual size:[/] [magenta]{diag.actual_size:,}[/] bytes'
    )
    if expected_hash:
        console.print(
            f'[bold]CAF hash (from path):[/] [cyan]{expected_hash}[/]'
        )
    console.print()
    console.print(f'[bold]CAF header[/] ([dim]{HEADER_SIZE} bytes[/]):')
    console.print(
        f'  [dim]Parent Hash (0:20):[/] [cyan]{diag.parent_hash.hex()}[/]'
    )
    console.print(f'    [dim]Root:[/] {_yes_no(diag.root_file)}')
    console.print(
        f'  [dim]Content Seed (20:36):[/] [cyan]{diag.content_seed.hex()}[/]'
    )
    console.print(
        f'  [dim]File Length (36:44):[/] [magenta]{diag.file_length:,}[/] '
        f'bytes'
    )
    console.print(
        f'    [dim]Matches actual:[/] {_yes_no(diag.file_length_matches)}'
    )
    console.print(
        f'  [dim]Header Checksum (44:52):[/] '
        f'[cyan]{diag.stored_header_checksum.hex()}[/]'
    )
    console.print(
        f'    [dim]Expected:[/] '
        f'[cyan]{diag.calculated_header_checksum.hex()}[/]'
    )
    console.print(f'    [dim]Valid:[/] {_yes_no(diag.header_checksum_valid)}')
    console.print(
        f'  [dim]Reserved (52:60):[/] [cyan]{diag.reserved.hex()}[/]'
    )
    console.print(f'    [dim]All zeros:[/] {_yes_no(diag.reserved_valid)}')
    console.print()
    console.print('[bold]Basic validation:[/]')
    console.print(
        f'  [dim]Header checksum valid:[/] '
        f'{_yes_no(diag.header_checksum_valid)}'
    )
    console.print(
        f'  [dim]Reserved bytes zero:[/] {_yes_no(diag.reserved_valid)}'
    )
    console.print(
        f'  [dim]File length matches actual:[/] '
        f'{_yes_no(diag.file_length_matches)}'
    )
    console.print(
        f'  [dim]File length >= header size:[/] '
        f'{_yes_no(diag.file_length_minimum)}'
    )

    if expected_hash and not diag.root_file:
        store_root = os.path.abspath(
            os.path.join(
                filepath,
                os.pardir,
                os.pardir,
                os.pardir,
                os.pardir,
            )
        )
        parent_path = hash_to_path(store_root, diag.parent_hash.hex())
        console.print()
        console.print('[bold]Parent path:[/]', Text(parent_path))


def _calculate_blake2b_160(filepath: str) -> str:
    blake2b = hashlib.blake2b(digest_size=20)
    with open(filepath, 'rb') as f:
        while chunk := f.read(BLOCK_SIZE):
            blake2b.update(chunk)
    return blake2b.hexdigest()


def _print_checksum_diagnostics(
    console: Console,
    expected_hash: str,
    actual_hash: str,
    checksum_matches: bool,
) -> None:
    console.print()
    console.print('[bold]File checksum[/] ([dim]BLAKE2b-160[/]):')
    if expected_hash:
        console.print(
            f'  [dim]Expected (from path):[/] [cyan]{expected_hash}[/]'
        )
    else:
        console.print(
            '  [dim]Expected (from path):[/] '
            '[dim]<unavailable: not in CAF layout>[/]'
        )
    console.print(f'  [dim]Actual:[/] [cyan]{actual_hash}[/]')
    console.print(f'  [dim]Matches:[/] {_yes_no(checksum_matches)}')


@dev.command()
@click.argument('filepath', type=click.Path(exists=True, dir_okay=False))
@click.option(
    '--verify-checksum',
    is_flag=True,
    default=False,
    help='Calculate the file BLAKE2b checksum and verify it matches the '
    'hash implied by the CAF path layout.',
)
def show(filepath: str, verify_checksum: bool) -> None:
    """Print diagnostic information about a CAF content file."""
    console = Console()
    expected_hash = parse_hash_from_path(filepath)
    diag = _load_caf_header_diagnostics(filepath)
    _print_caf_header_diagnostics(console, filepath, diag, expected_hash)

    exit_code = 0

    if verify_checksum:
        actual_hash = _calculate_blake2b_160(filepath)
        checksum_matches = bool(expected_hash) and actual_hash == expected_hash
        _print_checksum_diagnostics(
            console, expected_hash, actual_hash, checksum_matches
        )

        if not expected_hash or not checksum_matches or not diag.basic_valid:
            exit_code = 1

    if exit_code:
        raise SystemExit(exit_code)


@dev.command()
@click.argument('filepath', type=click.Path(exists=True))
@click.option(
    '--preset',
    type=click.Choice(['zero', 'random']),
    default='random',
    help='Corruption preset: "zero" fills with zeros, '
    '"random" fills with random bytes.',
)
@click.option(
    '--start',
    type=int,
    default=0,
    help='Starting byte offset for corruption.',
)
@click.option(
    '--length',
    type=int,
    default=100,
    help='Number of bytes to corrupt.',
)
@click.option(
    '--seed',
    type=int,
    help='Random seed for reproducible corruption '
    '(only applies to "random" preset).',
)
def corrupt_file(
    filepath: str, preset: str, start: int, length: int, seed: Optional[int]
) -> None:
    """Intentionally corrupt a file for testing verification.

    This command is used to test that caf correctly detects corruption.
    It will modify the specified byte range in the file according to the
    chosen preset.

    Examples:

    \b
    # Zero out bytes 100-199 in a file
    caf dev corrupt-file myfile.dat --preset zero --start 100 --length 100

    \b
    # Fill bytes 0-49 with random data
    caf dev corrupt-file myfile.dat --preset random --start 0 --length 50

    \b
    # Use a seed for reproducible corruption
    caf dev corrupt-file myfile.dat --preset random --seed 42
    """
    import mmap

    click.echo(f"Corrupting file: {filepath}")
    click.echo(f"Preset: {preset}")
    click.echo(
        f"Range: bytes {start} to {start + length - 1} ({length} bytes)"
    )

    # Get file size to validate parameters
    file_size = os.path.getsize(filepath)
    if start >= file_size:
        raise click.BadParameter(
            f"Start offset {start} is beyond file size {file_size}"
        )
    if start + length > file_size:
        truncated_len = file_size - start
        click.echo(
            f"Warning: Corruption range extends beyond file size. "
            f"Truncating to {truncated_len} bytes."
        )
        length = truncated_len

    # Apply corruption
    with open(filepath, 'r+b') as f:
        with mmap.mmap(f.fileno(), 0) as mm:
            if preset == 'zero':
                # Zero out the specified range
                mm[start : start + length] = b'\x00' * length
                click.echo(f"Zeroed out {length} bytes")
            elif preset == 'random':
                # Fill with random bytes
                if seed is not None:
                    random.seed(seed)
                    click.echo(f"Using random seed: {seed}")
                random_bytes = bytes(
                    random.randint(0, 255) for _ in range(length)
                )
                mm[start : start + length] = random_bytes
                click.echo(f"Filled {length} bytes with random data")

    click.echo("Corruption complete.")


@main.command()
@click.option(
    '--directory',
    help='The directory to verify. Defaults to current directory.',
    callback=current_directory,
)
@click.option(
    '--chunk-size',
    type=int,
    default=4096,
    help='Chunk size in bytes for corruption analysis. Smaller values provide '
    'more granular corruption detection but take longer. Common values: '
    '512 (fine-grained), 4096 (4KB blocks), 65536 (64KB chunks).',
)
def verify(directory: str, chunk_size: int) -> None:
    """Verify content addressable files and analyze corruption.

    This command verifies all CAF files in the specified directory and
    provides detailed corruption analysis if any files are corrupted.

    The --chunk-size option controls the granularity of corruption detection:

    \b
    - 512 bytes: Fine-grained analysis, slower but more precise
    - 4096 bytes: Standard 4KB block analysis (default)
    - 65536 bytes: Fast scanning for large files

    When corruption is detected, the verifier will:

    \b
    - Identify exact corrupted byte ranges
    - Analyze corruption patterns (zero-filled, sparse, random, etc.)
    - Provide visual corruption maps
    - Suggest recovery strategies based on patterns
    """
    console = Console()
    console.print(f"Verifying file contents in: [bold]{directory}[/]")
    console.print(f"[dim]Analysis chunk size: {chunk_size:,} bytes[/]")
    verifier = FileVerifier(directory, analysis_chunk_size=chunk_size)
    result = verifier.verify_files()
    if result.success:
        console.print("[green]✓[/] All files successfully verified.")
    else:
        console.print("[red]✗[/] Verification failed.")
        raise SystemExit(1)


if __name__ == '__main__':
    main()
