@passport_CRI_API
Feature: Passport CRI API

  @intialJWT_happy_path @passportCRI_API @pre-merge @dev
  Scenario: Acquire initial JWT and Passport Happy path
    Given Passport user has the user identity in the form of a signed JWT string for CRI Id passport-build and row number 6
    And Passport user sends a POST request to session endpoint
    And Passport user gets a session-id
    When Passport user sends a POST request to Passport endpoint using jsonRequest PassportValidJsonPayload
    And Passport user gets authorisation code
    And Passport user sends a POST request to Access Token endpoint passport-build
    Then User requests Passport CRI VC
    And Passport VC should contain validityScore 2 and strengthScore 4

  @passportCRI_API @pre-merge @dev
  Scenario: Acquire initial JWT and Passport Happy path
    Given Passport user has the user identity in the form of a signed JWT string for CRI Id passport-build and row number 6
    And Passport user sends a POST request to session endpoint
    And Passport user gets a session-id
    When Passport user sends a POST request to Passport endpoint using jsonRequest PassportValidJsonPayload
    And Passport user gets authorisation code
    And Passport user sends a POST request to Access Token endpoint passport-build
    Then User requests Passport CRI VC
    And Passport VC should contain validityScore 2 and strengthScore 4

  @passportCRI_API @pre-merge @dev
  Scenario: Passport Retry Journey Happy Path
    Given Passport user has the user identity in the form of a signed JWT string for CRI Id passport-build and row number 6
    And Passport user sends a POST request to session endpoint
    And Passport user gets a session-id
    When Passport user sends a POST request to Passport endpoint using jsonRequest PassportInvalidJsonPayload
    Then Passport check response should contain Retry value as true
    When Passport user sends a POST request to Passport endpoint using jsonRequest PassportValidJsonPayload
    And Passport check response should contain Retry value as false
    And Passport user gets authorisation code
    And Passport user sends a POST request to Access Token endpoint passport-build
    Then User requests Passport CRI VC
    And Passport VC should contain validityScore 2 and strengthScore 4

  @passportCRI_API @pre-merge @dev
  Scenario: Passport Retry Journey Happy Path
    Given Passport user has the user identity in the form of a signed JWT string for CRI Id passport-build and row number 6
    And Passport user sends a POST request to session endpoint
    And Passport user gets a session-id
    When Passport user sends a POST request to Passport endpoint using jsonRequest PassportInvalidJsonPayload
    Then Passport check response should contain Retry value as true
    When Passport user sends a POST request to Passport endpoint using jsonRequest PassportValidJsonPayload
    And Passport check response should contain Retry value as false
    And Passport user gets authorisation code
    And Passport user sends a POST request to Access Token endpoint passport-build
    Then User requests Passport CRI VC
    And Passport VC should contain validityScore 2 and strengthScore 4