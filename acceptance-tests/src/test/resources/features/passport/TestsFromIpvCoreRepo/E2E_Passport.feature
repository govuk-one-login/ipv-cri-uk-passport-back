Feature: E2E

  Scenario Outline: Passport details page happy path
    Given User on Orchestrator Stub and click on full journey route
    And clicks continue on the signed into your GOV.UK One Login page in build stub
    And user enters the data in Passport stub as a <PassportSubject>
    When user enters data in address stub and Click on submit data and generate auth code
    Then user should be on Fraud Check (Stub)
    When user enters data in fraud build stub and Click on submit data and generates auth code
    Then User should be on KBV page and click continue
    When user enters data in kbv stub and Click on submit data and generate auth code
    Then user should be successful in proving identity
    And User should be able to see the json response page
    And The test is complete and I close the driver

    Examples:
      | PassportSubject   |
      | PassportSubject   |

  Scenario Outline: address cri page back button recovery page
    Given User on Orchestrator Stub and click on full journey route
    And clicks continue on the signed into your GOV.UK One Login page in build stub
    And user enters the data in Passport stub as a <PassportSubject>
    When user clicks on browser back button
    Then user is redirected back to the Passport CRI build Stub
    When user Click on submit data and generates auth code
    Then User should see error recovery page and clicks on continue
    When user enters data in address stub and Click on submit data and generate auth code
    Then user should be on Fraud Check (Stub)
    When user enters data in fraud build stub and Click on submit data and generates auth code
    Then User should be on KBV page and click continue
    When user enters data in kbv stub and Click on submit data and generate auth code
    Then user should be successful in proving identity
    And The test is complete and I close the driver

    Examples:
      | PassportSubject   |
      | PassportSubject   |

  Scenario Outline: fraud cri page back button recovery page
    Given User on Orchestrator Stub and click on full journey route
    And clicks continue on the signed into your GOV.UK One Login page in build stub
    And user enters the data in Passport stub as a <PassportSubject>
    When user enters data in address stub and Click on submit data and generate auth code
    Then user should be on Fraud Check (Stub)
    When user clicks on browser back button
    Then user is redirected back to the address CRI Stub
    When user Click on submit data and generates auth code
    Then User should see error recovery page and clicks on continue
    And user should be on Fraud Check (Stub)
    When user enters data in fraud build stub and Click on submit data and generates auth code
    Then User should be on KBV page and click continue
    When user enters data in kbv stub and Click on submit data and generate auth code
    Then user should be successful in proving identity
    And The test is complete and I close the driver

    Examples:
      | PassportSubject   |
      | PassportSubject   |

  Scenario Outline: kbv cri page back button recovery page
    Given User on Orchestrator Stub and click on full journey route
    And clicks continue on the signed into your GOV.UK One Login page in build stub
    And user enters the data in Passport stub as a <PassportSubject>
    When user enters data in address stub and Click on submit data and generate auth code
    Then user should be on Fraud Check (Stub)
    When user enters data in fraud build stub and Click on submit data and generates auth code
    Then User should be on KBV (Stub)
    When user clicks on browser back button
    Then user is redirected back to the fraud CRI Stub
    When user Click on submit data and generates auth code
    Then User should see error recovery page and clicks on continue
    And User should be on KBV page and click continue
    When user enters data in kbv stub and Click on submit data and generate auth code
    Then user should be successful in proving identity
    And The test is complete and I close the driver

    Examples:
      | PassportSubject   |
      | PassportSubject   |

  Scenario: Passport IPV Technical Error Page Rebranding Changes
    Given User on Orchestrator Stub and click on full journey route
    And clicks continue on the signed into your GOV.UK One Login page in build stub
    And user does not enters the data in Passport stub and click on submit
    Then Branding changes for GOV.UK One login displayed
    And The test is complete and I close the driver

  @Staging @Integration
  Scenario Outline: Passport cri back button recovery page staging - <userName>
#   Auth
    Given User on Orchestrator Stub and click on full journey route
    And clicks continue on the signed into your GOV.UK One Login page
#   Passport CRI
    When User "<userName>" adds their passport details in passport page
#   Address CRI
    And user clicks on browser back button
    And user is redirected back to the Passport CRI Stub
    And user Click on submit data and generate auth code
    And User should see error recovery page and clicks on continue
    When the user "<userName>" "Successfully" adds their Address Details
#   Fraud CRI
    Then the user completes the Fraud Cri Check
    When User should be on KBV page and click continue
#    And user enters data in kbv stub and Click on submit data and generate auth code
#   KBV CRI
    When the user "<userName>" "Successfully" passes the KBV CRI Check
#    Then user should be on Fraud Check (Stub)
#    When user enters data in fraud build stub and Click on submit data and generates auth code
#    Then User should be on KBV page and click continue
#    When user enters data in kbv stub and Click on submit data and generate auth code
#   ID Validation
    Then the user should see that they have "<dbsCheckResult>" proved their identity using the Orchestrator Stub
    And The test is complete and I close the driver
    Examples:
      | userName           | dbsCheckResult |
      | KennethDecerqueira | Successfully   |

  @Staging @Integration
  Scenario Outline: address cri back button recovery page staging  - <userName>
#   Auth
    Given User on Orchestrator Stub and click on full journey route
    And clicks continue on the signed into your GOV.UK One Login page
#   Passport CRI
    When User "<userName>" adds their passport details in passport page
#   Address CRI
    And the user "<userName>" "Successfully" adds their Address Details
#   Fraud CRI
    And user clicks on browser back button
    And User should see error recovery page and clicks on continue
    And the user completes the Fraud Cri Check
#   KBV CRI
    When User should be on KBV page and click continue
#    When user enters data in kbv stub and Click on submit data and generate auth code
    And the user "<userName>" "Successfully" passes the KBV CRI Check
#   ID Validation
#    Then user should be on Fraud Check (Stub)
#    When user enters data in fraud build stub and Click on submit data and generates auth code
#    Then User should be on KBV page and click continue
#    When user enters data in kbv stub and Click on submit data and generate auth code
    Then the user should see that they have "<dbsCheckResult>" proved their identity using the Orchestrator Stub
    And The test is complete and I close the driver
    Examples:
      | userName           | dbsCheckResult |
      | KennethDecerqueira | Successfully   |

  @Staging @Integration
  Scenario Outline: fraud cri back button recovery page staging  - <userName>
#   Auth
    Given User on Orchestrator Stub and click on full journey route
    And clicks continue on the signed into your GOV.UK One Login page
#   Passport CRI
    When User "<userName>" adds their passport details in passport page
#   Address CRI
    And the user "<userName>" "Successfully" adds their Address Details
#   Fraud CRI
    And the user completes the Fraud Cri Check
    And user clicks on browser back button
    And the user completes the Fraud Cri Check
    And User should see error recovery page and clicks on continue
#   KBV CRI
    Then User should be on KBV page and click continue
#    When user enters data in kbv stub and Click on submit data and generate auth code
    When the user "<userName>" "Successfully" passes the KBV CRI Check
#   ID Validation
#    Then user should be on Fraud Check (Stub)
#    When user enters data in fraud build stub and Click on submit data and generates auth code
#    Then User should be on KBV (Stub)
#    When user clicks on browser back button
#    Then user is redirected back to the fraud CRI Stub
#    When user Click on submit data and generates auth code
#    Then User should see error recovery page and clicks on continue
#    And User should be on KBV page and click continue
#    When user enters data in kbv stub and Click on submit data and generate auth code
    Then the user should see that they have "<dbsCheckResult>" proved their identity using the Orchestrator Stub
    And The test is complete and I close the driver
    Examples:
      | userName           | dbsCheckResult |
      | KennethDecerqueira | Successfully   |

  @Staging @Integration
  Scenario Outline: Passport cri back button recovery page through hyperlink staging - <userName>
#   Auth
    Given User on Orchestrator Stub and click on full journey route
    And clicks continue on the signed into your GOV.UK One Login page
#   Passport CRI
    When User "<userName>" adds their passport details in passport page
#   Address CRI
    And user clicks on browser back button
    And user is redirected back to the Passport CRI Stub
    And user clicks on prove identity another way
    And User should see error recovery page and clicks on continue
    And the user "<userName>" "Successfully" adds their Address Details
#   Fraud CRI
    When the user completes the Fraud Cri Check
#    When user enters data in fraud build stub and Click on submit data and generates auth code
#   KBV CRI
    And User should be on KBV page and click continue
#    And user enters data in kbv stub and Click on submit data and generate auth code
    And the user "<userName>" "Successfully" passes the KBV CRI Check
#    Then User should be on KBV page and click continue
#    When user enters data in kbv stub and Click on submit data and generate auth code
#   ID Validation
    Then the user should see that they have "<dbsCheckResult>" proved their identity using the Orchestrator Stub
    And The test is complete and I close the driver
    Examples:
      | userName           | dbsCheckResult |
      | KennethDecerqueira | Successfully   |

  @Staging @Integration
  Scenario Outline: Passport cri back button recovery page through hyperlink-2 staging - <userName>
#   Auth
    Given User on Orchestrator Stub and click on full journey route
    And clicks continue on the signed into your GOV.UK account page
#   Passport CRI
    When User "<userName>" adds their passport details in passport page
#   Address CRI
    And user clicks on browser back button
    And user is redirected back to the Passport CRI Stub
    And user clicks on continue entering passport details
    And User should see error recovery page and clicks on continue
    And the user "<userName>" "Successfully" adds their Address Details
#   Fraud CRI
    And the user completes the Fraud Cri Check
#    And user enters data in fraud build stub and Click on submit data and generates auth code
#   KBV CRI
    Then User should be on KBV page and click continue
#    When user enters data in kbv stub and Click on submit data and generate auth code
    When the user "<userName>" "Successfully" passes the KBV CRI Check
#    Then User should be on KBV page and click continue
#    When user enters data in kbv stub and Click on submit data and generate auth code
#   ID Validation
    Then the user should see that they have "<dbsCheckResult>" proved their identity using the Orchestrator Stub
    And The test is complete and I close the driver
    Examples:
      | userName           | dbsCheckResult |
      | KennethDecerqueira | Successfully   |

  @Staging
  Scenario Outline: Identity Persistence Sign out page
    Given User on Orchestrator Stub and click on full journey route
    And clicks continue on the signed into your GOV.UK One Login page
    And user enters the data in Passport stub as a <PassportSubject>
    When user enters data in address stub and Click on submit data and generate auth code
    Then user should be on Fraud Check (Stub)
    When user enters data in fraud build stub and Click on submit data and generates auth code
    Then User should be on KBV page and click continue
    When user enters data in kbv stub and Click on submit data and generate auth code
    Then user should be successful in proving identity
    When the User navigates to the `Orchestrator Stub` page
    And the user signs back in with the same userId
    Then the user should be taken to the IPV Reuse Screen with One login changes
    When User clicks on Sign-out button
    Then Standard Sign-out page should be displayed
    And The test is complete and I close the driver

    Examples:
      | PassportSubject   |
      | PassportSubject   |