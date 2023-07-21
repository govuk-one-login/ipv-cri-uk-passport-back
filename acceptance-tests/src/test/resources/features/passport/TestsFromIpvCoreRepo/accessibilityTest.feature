######## currently not working, these tests will be moved to new passport CRI front repo and will be fixed in LIME-625 ########
Feature: Checking accessibility issues

#  @accessibility_test
#  Scenario: UI accessibility test
#    Given I am on the test page
#    When I run AXE Accessibility Test
#    Then the number of `Critical` or `Severe` or `Serious` issues detected must be zero
#
#  @accessibility_multiple
#  Scenario Outline: Testing multiple pages
#    Given I am on the "<Test Page>"
#    When I run AXE Accessibility Test
#    Then the number of `Critical` or `Severe` or `Serious` issues detected must be zero
#
#    Examples:
#    | Test Page     |
#    | successUrl    |
#    | transitionUrl |
#    | startUrl      |

  @Accessibility
  Scenario: UI accessibility test multi doc check page
    Given User on Orchestrator Stub and click on full journey route
    And clicks continue on the signed into your GOV.UK One Login page for Axe test
    When I run AXE Accessibility Test
    Then the number of `Critical` or `Severe` or `Serious` issues detected must be zero

  @Accessibility
  Scenario: UI accessibility test IPV Technical Error Page
    Given User on Orchestrator Stub and click on full journey route
    And clicks continue on the signed into your GOV.UK account page
    And user does not enters the data in Passport stub and click on submit
    When I run AXE Accessibility Test
    Then the number of `Critical` or `Severe` or `Serious` issues detected must be zero

  @Accessibility
  Scenario Outline: UI accessibility test IPV Success Page
    Given User on Orchestrator Stub and click on full journey route
    And clicks continue on the signed into your GOV.UK One Login page
    And user enters the data in Passport stub as a <PassportSubject>
    When user enters data in address stub and Click on submit data and generate auth code
    Then user should be on Fraud Check (Stub)
    When user enters data in fraud build stub and Click on submit data and generates auth code
    Then User should be on KBV page and click continue
    When user enters data in kbv stub and Click on submit data and generate auth code
    Then user should be successful in proving identity
    When I run AXE Accessibility Test
    Then the number of `Critical` or `Severe` or `Serious` issues detected must be zero

    Examples:
      | PassportSubject   |
      | PassportSubject   |

  @Accessibility
  Scenario Outline: UI accessibility test IPV Reuse Page
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
    When I run AXE Accessibility Test
    Then the number of `Critical` or `Severe` or `Serious` issues detected must be zero

    Examples:
      | PassportSubject   |
      | PassportSubject   |

  @Accessibility
  Scenario Outline: UI accessibility test Pre KBV transition page
    Given User on Orchestrator Stub and click on full journey route
    And clicks continue on the signed into your GOV.UK One Login page
    And user enters the data in Passport stub as a <PassportSubject>
    When user enters data in address stub and Click on submit data and generate auth code
    Then user should be on Fraud Check (Stub)
    When user enters data in fraud build stub and Click on submit data and generates auth code
    Then User should be on KBV page
    When I run AXE Accessibility Test
    Then the number of `Critical` or `Severe` or `Serious` issues detected must be zero

    Examples:
      | PassportSubject   |
      | PassportSubject   |

  @Accessibility
  Scenario: UI accessibility test ipvcore start page
    Given User on Orchestrator Stub and click on full journey route
    And User lands on IPVCore identity start page
    When I run AXE Accessibility Test
    Then the number of `Critical` or `Severe` or `Serious` issues detected must be zero

  @Accessibility
  Scenario: UI accessibility test passport doc page
    Given User on Orchestrator Stub and click on full journey route
    And clicks continue on the signed into your GOV.UK One Login page
    When I run AXE Accessibility Test
    Then the number of `Critical` or `Severe` or `Serious` issues detected must be zero

  @Accessibility
  Scenario Outline: UI accessibility attempt recovery page
    Given User on Orchestrator Stub and click on full journey route
    And clicks continue on the signed into your GOV.UK One Login page
    And user enters the data in Passport stub as a <PassportSubject>
    When user clicks on browser back button
    Then user is redirected back to the Passport CRI build Stub
    When user Click on submit data and generates auth code
    Then User should see error recovery page
    When I run AXE Accessibility Test
    Then the number of `Critical` or `Severe` or `Serious` issues detected must be zero

    Examples:
      | PassportSubject   |
      | PassportSubject   |

  @Accessibility
  Scenario Outline: UI accessibility test for KBV Thin
    Given User on Orchestrator Stub and click on full journey route
    And clicks continue on the signed into your GOV.UK account page
    And user enters the data in Passport stub as a <PassportSubject>
    When user enters data in address stub and Click on submit data and generate auth code
    Then user should be on Fraud Check (Stub)
    When user enters data in fraud build stub and Click on submit data and generates auth code
    Then User should be on KBV page and click continue
    When user enters data in kbv stub for KBV Thin and Click on submit data and generate auth code
    Then KBV Thin Error Page should be displayed
    When I run AXE Accessibility Test
    Then the number of `Critical` or `Severe` or `Serious` issues detected must be zero

    Examples:
      | PassportSubject   |
      | PassportSubject   |

  @Accessibility
  Scenario: UI accessibility technical unrecoverable error page
    Given User on Orchestrator Stub and click on error journey route
    When unrecoverable error page should be displayed
    And I run AXE Accessibility Test
    Then the number of `Critical` or `Severe` or `Serious` issues detected must be zero

  @Accessibility
  Scenario Outline: UI accessibility test for KBV fail
    Given User on Orchestrator Stub and click on full journey route
    And clicks continue on the signed into your GOV.UK account page
    And user enters the data in Passport stub as a <PassportSubject>
    When user enters data in address stub and Click on submit data and generate auth code
    Then user should be on Fraud Check (Stub)
    When user enters data in fraud build stub and Click on submit data and generates auth code
    Then User should be on KBV page and click continue
    When user enters data in kbv stub for KBV fail and Click on submit data and generate auth code
    Then KBV fail Error Page should be displayed
    When I run AXE Accessibility Test
    Then the number of `Critical` or `Severe` or `Serious` issues detected must be zero

    Examples:
      | PassportSubject   |
      | PassportSubject   |