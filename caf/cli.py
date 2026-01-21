import os
import random
import functools
from typing import Callable, Optional
from importlib.metadata import version

import click
from rich.console import Console

from caf.generator import FileGenerator
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
