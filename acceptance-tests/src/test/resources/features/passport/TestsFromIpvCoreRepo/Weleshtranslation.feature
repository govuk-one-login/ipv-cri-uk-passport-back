Feature: Welsh Language Test

  @Staging @Integration
  Scenario: The content in Passport CRI page displayed in Welsh
    Given User on Orchestrator Stub and click on full journey route
    And clicks continue on the signed into your GOV.UK account page
    When user updated cookies can see the stub content in Welsh
    Then the content is displayed in Welsh language in Passport CRI Page
    Then The test is complete and I close the driver

  @Smoke_test @Staging @Integration @staging
  Scenario Outline: Passport Journey in Welsh translation Happy Path
    Given User on Orchestrator Stub and click on full journey route
    And clicks continue on the signed into your GOV.UK account page
    And user updated cookies can see the stub content in Welsh
    When User "<PassportSubject>" adds their passport details
    Then User should be on Address CRI Page
    Then The test is complete and I close the driver

    Examples:
      |PassportSubject             |
      |PassportSubjectHappyDanny   |

  @Staging @Integration
  Scenario Outline: Passport details page unhappy path invalid passport Number
    Given User on Orchestrator Stub and click on full journey route
    And clicks continue on the signed into your GOV.UK account page
    And user updated cookies can see the stub content in Welsh
    When User "<PassportSubject>" adds their passport details
    Then proper error message for invalid passport number should be displayed in Welsh
    Then The test is complete and I close the driver

    Examples:
      |PassportSubject       |
      |InvalidPassportNumber |

  @Staging @Integration
  Scenario Outline: Invalid First Name
    Given User on Orchestrator Stub and click on full journey route
    And clicks continue on the signed into your GOV.UK account page
    And user updated cookies can see the stub content in Welsh
    When User "<PassportSubject>" adds their passport details
    Then proper error message for invalid first name should be displayed in Welsh
    Then The test is complete and I close the driver

    Examples:
      |PassportSubject  |
      |InvalidfirstName |

  @Staging @Integration
  Scenario Outline: Invalid Surname
    Given User on Orchestrator Stub and click on full journey route
    And clicks continue on the signed into your GOV.UK account page
    And user updated cookies can see the stub content in Welsh
    When User "<PassportSubject>" adds their passport details
    Then proper error message for invalid surname should be displayed in Welsh
    Then The test is complete and I close the driver

    Examples:
      |PassportSubject |
      |Invalidsurname  |

  @Staging @Integration
  Scenario Outline: Invalid Date of Birth
    Given User on Orchestrator Stub and click on full journey route
    And clicks continue on the signed into your GOV.UK account page
    And user updated cookies can see the stub content in Welsh
    When User "<PassportSubject>" adds their passport details
    Then proper error message for invalid dob should be displayed in Welsh
    Then The test is complete and I close the driver

    Examples:
      |PassportSubject    |
      |InvalidDateofBirth |

  @Staging @Integration
  Scenario Outline: Invalid Passport Expiry Date
    Given User on Orchestrator Stub and click on full journey route
    And clicks continue on the signed into your GOV.UK account page
    And user updated cookies can see the stub content in Welsh
    When User "<PassportSubject>" adds their passport details
    Then proper error message for invalid exp date should be displayed in Welsh
    Then The test is complete and I close the driver

    Examples:
      |PassportSubject  |
      |InvalidExpiryDate|

  @Staging @Integration
  Scenario Outline: Passport Retry Test Invalid Passport error in Welsh
    Given User on Orchestrator Stub and click on full journey route
    And clicks continue on the signed into your GOV.UK account page
    When User adds Invalid "<InvalidPassportSubject>"
    And  adds again Invalid "<InvalidPassportSubject>"
    And user updated cookies can see the non CRI content in Welsh
    Then we cannot prove your identity right now error page is displayed in Welsh
    Then The test is complete and I close the driver

    Examples:
      |InvalidPassportSubject |
      |PassportSubjectInvalid |

  @Build @PYIC-1981  # currently failing
  Scenario Outline: Passport IPV Success Page in Welsh lang
    Given User on Orchestrator Stub and click on full journey route
    And clicks continue on the signed into your GOV.UK account page
    And user enters the data in Passport stub as a <PassportSubject>
    When user enters data in address stub and Click on submit data and generate auth code
    Then user should be on Fraud Check (Stub)
    When user enters data in fraud stub and Click on submit data and generate auth code
    Then User should be on KBV page and click continue
    When user enters data in kbv stub and Click on submit data and generate auth code
    And user updated cookies can see the stub content in Welsh
    Then user should be successful in proving identity in Welsh
    Then The test is complete and I close the driver

    Examples:
      | PassportSubject   |
      | PassportSubject   |

  @Build @PYIC-1910
  Scenario: Passport IPV Technical Error Page in Welsh lang
    Given User on Orchestrator Stub and click on full journey route
    And clicks continue on the signed into your GOV.UK account page
    And user does not enters the data in Passport stub and click on submit
    And user updated cookies can see the stub content in Welsh
    Then technical error page should be displayed in Welsh
    Then The test is complete and I close the driver


#  To be updated with New user with KBV questions enabled
#  @Integration
#  Scenario Outline: Passport IPV Success Page in Welsh
#    Given user on build Orchestrator Stub and click on full journey route for mobile app
#    And clicks continue on the signed into your GOV.UK account page
#    And the "<userName>" successfully adds their Passport Details
#    And the user "<userName>" "Successfully" adds their Address Details
#    And the user completes the Fraud Cri Check
#    And the user "<userName>" "Successfully" passes the KBV CRI Check
#    When user updated cookies can see the stub content in Welsh
#    Then the user should see that they have "<dbsCheckResult>" proved their identity
#    Examples:
#      | userName            | dbsCheckResult |
#      | KennethDecerqueira  | Successfully   |