Feature: Passport Test (Orchestrator Stub Full Journey Route)

  @Smoke_test @Staging @Integration
  Scenario Outline: Passport details page happy path - <PassportSubject>
    Given I am on Orchestrator Stub
    And I click on Full journey route
    And clicks continue on the signed into your GOV.UK One Login page
    When User "<PassportSubject>" adds their passport details
    Then User should be on Address CRI Page
    Then The test is complete and I close the driver

    Examples:
      |PassportSubject             |
      |PassportSubjectHappyDanny   |
      |PassportSubjectHappyKenneth |
      |PassportSubjectHappySuzie   |
      |PassportSubjectHappySandra  |
      |PassportSubjectHappyBen     |
      |PassportSubjectHappyAlex    |

  @Staging @Integration
  Scenario Outline: Passport details page unhappy path
    Given I am on Orchestrator Stub
    And I click on Full journey route
    And clicks continue on the signed into your GOV.UK One Login page
    When User "<PassportSubject>" adds their passport details
    Then proper error message for invalid passport number should be displayed
    Then The test is complete and I close the driver

    Examples:
      |PassportSubject      |
      |InvalidPassportNumber|

  @Staging @Integration
  Scenario Outline: Invalid Surname
    Given I am on Orchestrator Stub
    And I click on Full journey route
    And clicks continue on the signed into your GOV.UK One Login page
    When User "<PassportSubject>" adds their passport details
    Then proper error message for invalid Surname should be displayed
    Then The test is complete and I close the driver

    Examples:
      |PassportSubject |
      |Invalidsurname  |

  @Staging @Integration
  Scenario Outline: Invalid First Name
    Given I am on Orchestrator Stub
    And I click on Full journey route
    And clicks continue on the signed into your GOV.UK One Login page
    When User "<PassportSubject>" adds their passport details
    Then proper error message for invalid First Name should be displayed
    Then The test is complete and I close the driver

    Examples:
      |PassportSubject |
      |InvalidfirstName|

  @Staging @Integration
  Scenario Outline: Invalid Date of Birth
    Given I am on Orchestrator Stub
    And I click on Full journey route
    And clicks continue on the signed into your GOV.UK One Login page
    When User "<PassportSubject>" adds their passport details
    Then proper error message for invalid Date of Birth should be displayed
    Then The test is complete and I close the driver

    Examples:
      |PassportSubject   |
      |InvalidDateofBirth|

  @Staging @Integration
  Scenario Outline: Invalid Passport Expiry Date
    Given I am on Orchestrator Stub
    And I click on Full journey route
    And clicks continue on the signed into your GOV.UK One Login page
    When User "<PassportSubject>" adds their passport details
    Then proper error message for invalid Expiry Date should be displayed
    Then The test is complete and I close the driver

    Examples:
      |PassportSubject  |
      |InvalidExpiryDate|

  @Staging @Integration
  Scenario Outline: Passport Retry Test Happy Path
    Given I am on Orchestrator Stub
    And I click on Full journey route
    And clicks continue on the signed into your GOV.UK One Login page
    When User adds Invalid "<InvalidPassportSubject>" and then adds valid "<PassportSubject>"
    Then User should be on Address CRI Page
    Then The test is complete and I close the driver

    Examples:
      |InvalidPassportSubject  | PassportSubject           |
      |PassportSubjectInvalid  | PassportSubjectHappyDanny |

  @Staging @Integration
  Scenario Outline: Passport Retry Test Invalid Passport
    Given I am on Orchestrator Stub
    And I click on Full journey route
    And clicks continue on the signed into your GOV.UK One Login page
    When User adds Invalid "<InvalidPassportSubject>"
    And  adds again Invalid "<InvalidPassportSubject>"
    Then we cannot prove your identity right now error page is displayed
    Then The test is complete and I close the driver

    Examples:
      |InvalidPassportSubject |
      |PassportSubjectInvalid |

  @Staging @Integration
  Scenario: Passport Escape route unable to prove identity unhappy path
    Given I am on Orchestrator Stub
    And I click on Full journey route
    And clicks continue on the signed into your GOV.UK One Login page
    When User clicks prove your identity in another way
    Then  Prove your identity in another way is displayed
    Then The test is complete and I close the driver

  @Staging @Integration
  Scenario Outline: Passport Escape route Passport Retry
    Given I am on Orchestrator Stub
    And I click on Full journey route
    And clicks continue on the signed into your GOV.UK One Login page
    When User clicks Try to Enter Passport details and redirected back to passport page
    And User "<PassportSubject>" adds their passport details
    Then User should be on Address CRI Page
    Then The test is complete and I close the driver

    Examples:
      |PassportSubject            |
      |PassportSubjectHappyDanny  |

  @Staging @Integration
  Scenario Outline: Passport Escape Route 2nd retry Happy Path
    Given I am on Orchestrator Stub
    And I click on Full journey route
    And clicks continue on the signed into your GOV.UK One Login page
    When User adds Invalid "<InvalidPassportSubject>" and then adds through retry valid "<PassportSubject>"
    Then User should be on Address CRI Page
    Then The test is complete and I close the driver

    Examples:
      |InvalidPassportSubject  | PassportSubject           |
      |PassportSubjectInvalid  | PassportSubjectHappyDanny |

  @Staging @Integration
  Scenario Outline: Passport Escape Route 2nd retry Unhappy Path
    Given I am on Orchestrator Stub
    And I click on Full journey route
    And clicks continue on the signed into your GOV.UK One Login page
    When User adds Invalid "<InvalidPassportSubject>"
    And User clicks Try to Enter Passport details and redirected back to passport page
    And  adds again Invalid "<InvalidPassportSubject>"
    Then we cannot prove your identity right now error page is displayed
    Then The test is complete and I close the driver

    Examples:
      |InvalidPassportSubject  |
      |PassportSubjectInvalid  |