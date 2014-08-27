import os
import random
import functools

import click

from caf.generator import FileGenerator
from caf.generator import FileVerifier

__version__ = '0.0.1'


SIZE_TYPES = {
    'kb': 1024,
    'mb': 1024 ** 2,
    'gb': 1024 ** 3,
    'tb': 1024 ** 4,
}


def current_directory(ctx, param, value):
    if value is None:
        return os.getcwd()
    else:
        return value


def convert_to_bytes(ctx, param, value):
    is_size_identifier = (
        len(value) >= 2 and value[-2:].lower() in SIZE_TYPES)
    if not is_size_identifier:
        try:
            return int(value)
        except ValueError:
            raise click.BadParameter("Invalid size specifier")
    else:
        multiplier = SIZE_TYPES[value[-2:].lower()]
        return int(value[:-2]) * multiplier


def identity(value):
    return lambda: value


class FileSizeType(click.ParamType):
    # ``name`` is used by the --help output.
    name = 'filesize'

    RANDOM_FUNCTION = {
        'normal': lambda Mean, StdDev: abs(int(random.gauss(Mean, StdDev))),
        'gamma': lambda Alpha, Beta: abs(int(random.gammavariate(Alpha, Beta))),
        'lognormal': lambda Mean, StdDev: abs(int(random.lognormvariate(Mean, StdDev))),
    }

    def convert(self, value, param, ctx):
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
                self.fail('Bad value for --filesize: %s\n\nShould be '
                          'startsize-endsize (e.g. 1mb-5mb).' % value)
            start = self._parse_with_size_suffix(parts[0])
            end = self._parse_with_size_suffix(parts[1])
            return lambda: random.randint(start, end)
        elif self._is_size_identifier(value):
            return identity(self._parse_with_size_suffix(value))
        else:
            self.fail('Unknown size specifier "%s"' % value, param, ctx)

    def _is_size_identifier(self, value):
        return len(value) >= 2 and value[-2:].lower() in SIZE_TYPES

    def _parse_with_size_suffix(self, value):
        if self._is_size_identifier(value):
            multiplier = SIZE_TYPES[value[-2:].lower()]
            return int(value[:-2]) * multiplier
        else:
            return int(value)

    def _parse_shorthand(self, value):
        # Shorthand is of the form
        # A=1,B=3,C=3
        shorthand_dict = {}
        for item in value.split(','):
            k, v = item.split('=')
            shorthand_dict[k] = v
        if 'Type' not in shorthand_dict:
            self.fail("Missing Type=<type> in file size specifier: %s" %
                      value)
        param_type = shorthand_dict.pop('Type')
        if param_type not in self.RANDOM_FUNCTION:
            self.fail("Unknown Type '%s', must be one of: %s" %
                      (param_type, ','.join(self.RANDOM_FUNCTION)))
        for key, value in shorthand_dict.items():
            shorthand_dict[key] = self._parse_with_size_suffix(value)
        func = functools.partial(self.RANDOM_FUNCTION[param_type],
                                 **shorthand_dict)
        return func


@click.group()
def main():
    pass


@main.command()
@click.option('--directory',
              help='The directory where files will be generated.',
              callback=current_directory)
@click.option('--max-files', type=int,
              help='The maximum number of files to gnerate.')
@click.option('--max-disk-usage', callback=convert_to_bytes,
              help='The maximum disk space to use when generating files.')
@click.option('--file-size', default=4096,
              type=FileSizeType(),
              help='The size of the files that are generated.  '
              'Value is either in bytes or can be suffixed with '
              'kb, mb, gb, etc.  Suffix is case insensitive (we '
              'know what you mean).')
def gen(directory, max_files, max_disk_usage, file_size):
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
    # "file_size" is actually a no-arg function created by
    # FileSizeType.  Is there a way in click to specify the destination?
    file_size_chooser = file_size
    generator = FileGenerator(directory, max_files, max_disk_usage,
                              file_size_chooser)
    generator.generate_files()


@main.command()
@click.argument('rootdir', default='.')
def verify(rootdir):
    click.echo("Verifying file contents in: %s" % rootdir)
    verifier = FileVerifier(rootdir)
    verifier.verify_files()
    click.echo("All files successfully verified.")


if __name__ == '__main__':
    main()
