Feature: Passport Test (Through Passport Stub)

  @passport-build
  Scenario: Successful journey from core stub
    Given I navigate to the IPV Core Stub
    And I click the passport CRI for the testEnvironment
    And I search for passport user number 5 in the Experian table
    Then I should be on the passport details page
    When I fill in my details
    And I click continue
    Then I should be on the core stub Verifiable Credentials page
    And I should see passport data in JSON
    Then The test is complete and I close the driver