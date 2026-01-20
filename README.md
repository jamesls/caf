# caf

Caf (content addressable files) is a CLI utility that allows you to:

* Create random files using `caf gen`
* Verify the generated files have not been tampered with `caf verify`

That's it.  Generate files with random content and verify the files haven't
changed.  The `caf gen` command gives control over both the number of files
to create as well as the size of the files created.  It even lets you specify
the distribution of file sizes (more on that in a bit).

Caf is also designed in a way that allows for parallel file generation as well
as parallel file validation.  It can seamlessly scale up to billions of files.

For example, create a set of random files up to 10MB (the default file size
is 4k):

```
$ caf gen --max-disk-usage 10MB
```

You can then verify the files are all there:

```
$ caf verify
```

The `--help` output of the `caf gen` command contains many more examples.
