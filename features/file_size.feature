Feature: Specify Size of Created Files

  As a user
  I want to be able to control the size of the files generated
  So that I can test files of various sizes

  Scenario: Specify size as bytes
    Given a new working directory
    When I run "caf gen --max-files 5 --file-size 4096"
    Then the size of each generated file should be 4096

  Scenario: Specify size as kilobytes
    Given a new working directory
    When I run "caf gen --max-files 5 --file-size 16kb"
    Then the size of each generated file should be 16384

  Scenario: Specify size as megabytes
    Given a new working directory
    When I run "caf gen --file-size 1MB --max-files 5"
    Then the size of each generated file should be 1048576

  Scenario: Specify size as range
    Given a new working directory
    When I run "caf gen --file-size 4048-8096 --max-files 5"
    Then the size of each generated file should be between 4048 and 8096
