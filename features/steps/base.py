from behave import *
import os
from subprocess import Popen, PIPE
from hamcrest import assert_that, equal_to

import tempfile


def get_all_generated_files(rootdir):
    for root, _, filenames in os.walk(rootdir):
        if '.metadata' in root:
            # Don't iterate over the files in .metadata,
            # these aren't the randomly generates files.
            continue
        for filename in filenames:
            full_path = os.path.join(root, filename)
            yield full_path


class CommandResult(object):
    def __init__(self, stdout, stderr, rc):
        self.stdout = stdout
        self.stderr = stderr
        self.rc = rc


@given(u'a new working directory')
def step_impl(context):
    dirname = tempfile.mkdtemp()
    context.working_dir = dirname


@when(u'I run "{}"')
def step_impl(context, command):
    original = os.getcwd()
    os.chdir(context.working_dir)
    try:
        p = Popen(command, shell=True, stderr=PIPE, stdout=PIPE)
        stdout, stderr = p.communicate()
        result = CommandResult(stdout, stderr, p.returncode)
        context.command_result = result
        assert_that(p.returncode, equal_to(0), stderr)
    finally:
        os.chdir(original)


@then(u'the total disk usage of files generated should be {total_size}')
def step_impl(context, total_size):
    disk_usage = 0
    for full_path in get_all_generated_files(context.working_dir):
        file_size = os.stat(full_path).st_size
        disk_usage += file_size

    assert_that(int(total_size), equal_to(disk_usage))
    assert_that(disk_usage, equal_to(int(total_size)))


@then(u'the total number of files created should be {num_files}')
def step_impl(context, num_files):
    actual_count = 0
    for full_path in get_all_generated_files(context.working_dir):
        actual_count += 1
    assert_that(actual_count, equal_to(int(num_files)))


@then(u'the size of each generated file should be between {min_file_size} and {max_file_size}')
def step_impl(context, min_file_size, max_file_size):
    for full_path in get_all_generated_files(context.working_dir):
        actual_file_size = os.stat(full_path).st_size
        is_within_range = int(min_file_size) <= actual_file_size <= int(max_file_size)
        assert_that(is_within_range, equal_to(True), actual_file_size)


@then(u'the size of each generated file should be {file_size}')
def step_impl(context, file_size):
    for full_path in get_all_generated_files(context.working_dir):
        actual_file_size = os.stat(full_path).st_size
        assert_that(int(file_size), equal_to(actual_file_size))
