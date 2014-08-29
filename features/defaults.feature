Feature: Have Reasonable Defaults

  As a user
  I want to be able to run caf gen/verify without any arguments
  So that I quickly get started without learning all the arguments.

  Scenario: Generating files without any paramteres
    Given a new working directory
    When I run "caf gen"
    Then the total number of files created should be "100"
