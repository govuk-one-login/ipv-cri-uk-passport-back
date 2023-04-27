Feature: Passport Test (Full Journey Route)

  @Smoke_test @Staging @Integration
  Scenario Outline: Passport details page happy path - <PassportSubject>
    Given I am on Orchestrator Stub
    And I click on Full journey route
    And clicks continue on the signed into your GOV.UK One Login page
    When User "<PassportSubject>" adds their passport details
    Then User should be on Address CRI Page

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
    Examples:
      |PassportSubject  |
      |InvalidExpiryDate|

  @Staging @Integration @PYIC-1570
  Scenario Outline: Passport Retry Test Happy Path
    Given I am on Orchestrator Stub
    And I click on Full journey route
    And clicks continue on the signed into your GOV.UK One Login page
    When User adds Invalid "<InvalidPassportSubject>" and then adds valid "<PassportSubject>"
    Then User should be on Address CRI Page
    Examples:
      |InvalidPassportSubject  | PassportSubject           |
      |PassportSubjectInvalid  | PassportSubjectHappyDanny |

  @Staging @Integration @PYIC-1570
  Scenario Outline: Passport Retry Test Invalid Passport
    Given I am on Orchestrator Stub
    And I click on Full journey route
    And clicks continue on the signed into your GOV.UK One Login page
    When User adds Invalid "<InvalidPassportSubject>"
    And  adds again Invalid "<InvalidPassportSubject>"
    Then we cannot prove your identity right now error page is displayed
    Examples:
      |InvalidPassportSubject |
      |PassportSubjectInvalid |

  @Staging @Integration @PYIC-1636
  Scenario: Passport Escape route unable to prove identity unhappy path
    Given I am on Orchestrator Stub
    And I click on Full journey route
    And clicks continue on the signed into your GOV.UK One Login page
    When User clicks prove your identity in another way
    Then  Prove your identity in another way is displayed

  @Staging @Integration @PYIC-1636
  Scenario Outline: Passport Escape route Passport Retry
    Given I am on Orchestrator Stub
    And I click on Full journey route
    And clicks continue on the signed into your GOV.UK One Login page
    When User clicks Try to Enter Passport details and redirected back to passport page
    And User "<PassportSubject>" adds their passport details
    Then User should be on Address CRI Page

    Examples:
      |PassportSubject            |
      |PassportSubjectHappyDanny  |

  @Staging @Integration @PYIC-1636
  Scenario Outline: Passport Escape Route 2nd retry Happy Path
    Given I am on Orchestrator Stub
    And I click on Full journey route
    And clicks continue on the signed into your GOV.UK One Login page
    When User adds Invalid "<InvalidPassportSubject>" and then adds through retry valid "<PassportSubject>"
    Then User should be on Address CRI Page

    Examples:
      |InvalidPassportSubject  | PassportSubject           |
      |PassportSubjectInvalid  | PassportSubjectHappyDanny |

  @Staging @Integration @PYIC-1636
  Scenario Outline: Passport Escape Route 2nd retry Unhappy Path
    Given I am on Orchestrator Stub
    And I click on Full journey route
    And clicks continue on the signed into your GOV.UK One Login page
    When User adds Invalid "<InvalidPassportSubject>"
    And User clicks Try to Enter Passport details and redirected back to passport page
    And  adds again Invalid "<InvalidPassportSubject>"
    Then we cannot prove your identity right now error page is displayed

    Examples:
      |InvalidPassportSubject  |
      |PassportSubjectInvalid  |


#  @Integration @PYIC-1796
#  Scenario Outline: Test to Validate CI 'A01'
#    Given user enters data as a <PassportSubject>
#    When user clicks on continue
#    Then the user should be on `What's your current home address` page
#    When the user enters their Michelle postcode and click on `Find address` button
#    And the user selects their address from the dropdown menu and click on `Select address` button
#    And the user enters the year that they started living at that address
#    Then the user should be shown their address and the move year on `Check your details` page
#    When the user clicks on `Continue` on `Check your details` page
#    Then the user should land on `Fraud Check Stub` page
#    When the user completes Fraud Check Stub
#    Then the user should land on `Answer Security Questions` page
#    When the user clicks on `Continue` on `Sorry Cant Prove your identity` page
#    Then the user should land on user information page and get the ci as expected
#    Examples:
#      |PassportSubject              |
#      |PassportSubjectHappyMichelle |

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
#    And Expiry time should be 6 months from the nbf in the JSON payload