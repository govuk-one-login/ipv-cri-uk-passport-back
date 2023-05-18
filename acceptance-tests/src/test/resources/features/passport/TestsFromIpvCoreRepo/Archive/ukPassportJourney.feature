Feature: UK passport journey on the Staging Orchestrator Stub

  @happy_passport
  Scenario: Happy Path with Kenneth Decerqueira
    Given User on Orchestrator Stub and click on Debug journey route
    Then I should be on `Enter your details exactly as they appear on your UK passport` page
    When I run AXE Accessibility Test
    Then the number of `Critical` or `Severe` or `Serious` issues detected must be zero
    When I enter Kenneth Decerqueira's details and click Continue
    Then GPG45 Score for Strength must be 4 and Validity must be 2
    When I click on Authorize and Return
    Then I should see Verifiable Credentials










