Feature: Passport API tests

# Happy path with Kenneth Decerqueira
  @passport_api_tests
  @valid_passport_api_tests
  Scenario: Testing API with valid passport
    Given I have Kenneth Decerqueira
    When I send a GET request with valid UK passport
    Then I should get passport valid message and validity value must be 2

# Unhappy path with Al Bundy
  @passport_api_tests
  @invalid_passport_api_tests
  Scenario: Testing API with invalid passport
    Given I have Al Bundy
    When I send a GET request with invalid UK passport
    Then I should get passport invalid message and validity value must be 0
    