Feature: Full journey with UK Passport CRI

  @passportSmokeBuild
  Scenario: Successful journey from core stub
    Given I navigate to the IPV Core Stub
    And I click the passport CRI for the testEnvironment
    And I search for passport user number 5 in the Experian table
    Then I should be on the passport details page
    When I fill in my details
    And I click continue
    Then I should be on the core stub Verifiable Credentials page
    And I should see passport data in JSON

  @passportSmokeStaging
  Scenario: Successful journey from core
    Given User on Orchestrator Stub and click on Debug journey route
    And I fill in my details
    And I click continue
    Then I should be on the core front debug page
    And I should see GPG45 Score displayed
    When I click on Authorize and Return
    Then I should see User information displayed
    When I click on Verifiable Credentials
#    Then I should see Mary in the JSON payload
