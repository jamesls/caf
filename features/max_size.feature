Feature: Specify Maximum Disk Usage

  As a user
  I want to be able to specity the maximum amount of disk space to use
  So that I can make sure I don't run out of disk space.

  Scenario: Specifying maximum disk usage in bytes
    Given a new working directory
    When I run "caf gen --max-disk-usage 16384 --file-size 4096"
    Then the total disk usage of files generated should be "16384"

  Scenario: Specifying maximum disk usage in bytes without a file size
    Given a new working directory
    When I run "caf gen --max-disk-usage 16384"
    Then the total disk usage of files generated should be "16384"

  Scenario: Specifying maximum disk usage in megabytes
    Given a new working directory
    When I run "caf gen --max-disk-usage 1MB"
    Then the total disk usage of files generated should be "1048576"
