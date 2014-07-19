import os

import click

from caf.generator import FileGenerator
from caf.generator import FileVerifier

__version__ = '0.0.1'


def current_directory(ctx, param, value):
    if value is None:
        return os.getcwd()
    else:
        return value


class FileSizeType(click.ParamType):
    # ``name`` is used by the --help output.
    name = 'filesize'

    SIZE_TYPES = {
        'kb': 1024,
        'mb': 1024 ** 2,
        'gb': 1024 ** 3,
        'tb': 1024 ** 4,
    }

    def convert(self, value, param, ctx):
        if isinstance(value, int):
            # A value has already been specified,
            # assume that its an int.
            return value
        elif len(value) >= 2 and value[-2:].lower() in self.SIZE_TYPES:
            multiplier = self.SIZE_TYPES[value[-2:].lower()]
            return int(value[:-2]) * multiplier
        else:
            self.fail('Unknown size specifier "%s"' % value, param, ctx)


@click.group()
def main():
    pass


@main.command()
@click.option('--directory',
              help='The directory where files will be generated.',
              callback=current_directory)
@click.option('--max-files', type=int, default=100,
              help='The maximum number of files to gnerate.')
@click.option('--max-disk-usage',
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

        caf gen --file-size Type=gamma,Alpha=20MB,StdDev=1MB

    As well as an exponential distribution (Mean is 1 / lambda):

        caf gen --file-size Type=exponential,Mean=10MB

    And finally a lognormal distribution:

        caf gen --file-size Type=lognormal,Mean=10MB,StdDev=1MB

    """
    #size_chooser = create_size_chooser(file_size)
    generator = FileGenerator(directory, max_files, max_disk_usage,
                              file_size)
    generator.generate_files()



@main.command()
@click.argument('rootdir', default='.')
def verify(rootdir):
    click.echo("Verifying file contents in: %s" % rootdir)
    verifier = FileVerifier(rootdir)
    verifier.verify_files()


if __name__ == '__main__':
    main()

