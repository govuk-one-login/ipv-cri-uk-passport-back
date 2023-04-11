Feature: Passport Test

 Background:
    Given I navigate to the IPV Core Stub
    And I click the passport CRI for the testEnvironment
    Then I search for passport user number 5 in the Experian table
    Then I check the page title is Enter your details exactly as they appear on your UK passport – Prove your identity – GOV.UK
    And I assert the URL is valid

  @Passport_test @build @staging @integration
  Scenario: Check the Unrecoverable error/ Unknown error in Passport CRI
    Given I delete the cri_passport_service_session cookie to get the unexpected error
    When I check the page title is Page not found – GOV.UK
    And The test is complete and I close the driver

# Not valuable as tab title ot changing in passport
#  @Passport_test @build
#  Scenario Outline: Error tab title validation
#    And I check the page title is Enter your details exactly as they appear on your UK passport – Prove your identity – GOV.UK
#    Then User enters data as a <PassportSubject>
#    And User clicks on continue
#    Then I check the page title is Error: Enter your details exactly as they appear on your UK passport – Prove your identity – GOV.UK
#    And The test is complete and I close the driver
#    Examples:
#      |PassportSubject             |
#      |NoLastName   |
#      |NoFirstName |
#      |NoDateOfBirth   |
#      |NoValidToDate  |
#      |NoPassportNumber |
#      |InvalidFirstNameWithNumbers|
#      |InvalidFirstNameWithSpecialCharacters|
#      |DateOfBirthWithSpecialCharacters     |
#      |InvalidDateOfBirth|
#      |DateOfBirthInFuture            |
#      |ValidToDateWithSpecialCharacters|
#      |ValidToDateInPast |
#      |PassportNumberWithSpecialChar|