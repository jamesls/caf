import click

__version__ = '0.0.1'


@click.group()
def main():
    pass


@main.command()
def gen():
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
    pass


if __name__ == '__main__':
    main()

