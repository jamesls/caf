Feature: Verification of file generation

  As a user
  I want to be able to verify the generated files
  So that I can be sure that the files have not been corrupted

  Scenario: Verification succeeds
    Given a new working directory
      and a new caf directory
    When I run the verification process
    Then the verification should succeed

  Scenario: Verification fails
    Given a new working directory
      and a new caf directory
    When I run remove a random file
     and I run the verification process
    Then the verification should fail
