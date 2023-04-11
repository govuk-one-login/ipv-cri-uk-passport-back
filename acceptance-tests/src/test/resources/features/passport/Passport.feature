Feature: Passport Test

  Background:
    Given I navigate to the IPV Core Stub
    And I click the passport CRI for the testEnvironment
    And I search for passport user number 5 in the Experian table

  @Passport_test @build @staging @integration @smoke
  Scenario Outline: Passport details page happy path
    Given User enters data as a <PassportSubject>
    When User clicks on continue
    Then I navigate to the passport verifiable issuer to check for a Valid response
    And JSON payload should contain validity score 2 and strength score 4
    And JSON response should contain documentNumber 321654987 same as given passport
    And The test is complete and I close the driver
    Examples:
      |PassportSubject             |
      |PassportSubjectHappyBilly   |

  @Passport_test
  Scenario Outline: Passport details page unhappy path with InvalidPassportDetails
    Given User enters data as a <PassportSubject>
    When User clicks on continue
    Then I navigate to the passport verifiable issuer to check for a Invalid response
    And JSON response should contain error description Authorization permission denied and status code as 302
    And The test is complete and I close the driver
    Examples:
      |PassportSubject      |
      |PassportSubjectUnhappySelina |

  @Passport_test @build @staging @integration
  Scenario Outline: Passport details page unhappy path with IncorrectPassportNumber
    Given User enters data as a <PassportSubject>
    When User clicks on continue
    Then Proper error message for Could not find your details is displayed
    When User clicks on continue
    Then I navigate to the passport verifiable issuer to check for a Valid response
    And JSON payload should contain ci D02, validity score 0 and strength score 4
    And JSON response should contain documentNumber 887766551 same as given passport
    And The test is complete and I close the driver
    Examples:
      |PassportSubject      |
      |IncorrectPassportNumber |

  @Passport_test @build @staging @integration
  Scenario Outline: Passport details page unhappy path with IncorrectDateOfBirth
    Given User enters data as a <PassportSubject>
    When User clicks on continue
    Then Proper error message for Could not find your details is displayed
    When User clicks on continue
    Then I navigate to the passport verifiable issuer to check for a Valid response
    And JSON payload should contain ci D02, validity score 0 and strength score 4
    And The test is complete and I close the driver
    Examples:
      |PassportSubject |
      |IncorrectDateOfBirth |

  @Passport_test @build @staging @integration
  Scenario Outline: Passport details page unhappy path with IncorrectFirstName
    Given User enters data as a <PassportSubject>
    When User clicks on continue
    Then Proper error message for Could not find your details is displayed
    When User clicks on continue
    Then I navigate to the passport verifiable issuer to check for a Valid response
    And JSON payload should contain ci D02, validity score 0 and strength score 4
    And The test is complete and I close the driver
    Examples:
      |PassportSubject |
      |IncorrectFirstName|

  @Passport_test @build @staging @integration
  Scenario Outline: Passport details page unhappy path with IncorrectLastName
    Given User enters data as a <PassportSubject>
    When User clicks on continue
    Then Proper error message for Could not find your details is displayed
    When User clicks on continue
    Then I navigate to the passport verifiable issuer to check for a Valid response
    And JSON payload should contain ci D02, validity score 0 and strength score 4
    And The test is complete and I close the driver
    Examples:
      |PassportSubject |
      |IncorrectLastName|

# Invalid test valid to not checked in DCS stub
#  @Passport_test @build @staging @integration
#  Scenario Outline: Passport details page unhappy path with IncorrectValidToDate
#    Given User enters data as a <PassportSubject>
#    When User clicks on continue
#    Then Proper error message for Could not find your details is displayed
#    When User clicks on continue
#    Then I navigate to the Passport verifiable issuer to check for a Valid response
#    And JSON payload should contain ci D02, validity score 0 and strength score 3
#    And The test is complete and I close the driver
#    Examples:
#      |PassportSubject |
#      |IncorrectValidToDate|

  @Passport_test @build @staging @integration @smoke
  Scenario Outline: Passport Retry Test Happy Path
    Given User enters invalid passport details
    When User clicks on continue
    Then Proper error message for Could not find your details is displayed
    When User Re-enters data as a <PassportSubject>
    And User clicks on continue
    Then I navigate to the passport verifiable issuer to check for a Valid response
    And JSON payload should contain validity score 2 and strength score 4
    And The test is complete and I close the driver
    Examples:
      |PassportSubject |
      |PassportSubjectHappyBilly |

  @Passport_test @build @staging @integration @smoke
  Scenario Outline: Passport User failed second attempt
    Given User enters invalid passport details
    When User clicks on continue
    Then Proper error message for Could not find your details is displayed
    When User Re-enters data as a <PassportSubject>
    And User clicks on continue
    Then I navigate to the passport verifiable issuer to check for a Valid response
    And JSON payload should contain ci D02, validity score 0 and strength score 4
    And The test is complete and I close the driver
    Examples:
      |PassportSubject |
      |IncorrectPassportNumber |

  @Passport_test @build @staging @integration @smoke
  Scenario: Passport User cancels after failed first attempt
    Given User enters invalid passport details
    When User clicks on continue
    Then Proper error message for Could not find your details is displayed
    When User click on ‘prove your identity another way' Link
    And User selects prove another way radio button
    Then I navigate to the passport verifiable issuer to check for a Valid response
    And JSON payload should contain ci D02, validity score 0 and strength score 4
    And The test is complete and I close the driver

  @Passport_test @smoke
  Scenario: Passport User cancels before first attempt via prove your identity another way route
    Given User click on ‘prove your identity another way' Link
    Then I navigate to the passport verifiable issuer to check for a Invalid response
    And JSON response should contain error description Authorization permission denied and status code as 302
    And The test is complete and I close the driver

###########   Field Validations ##########
  @Passport_test @build @staging @integration
  Scenario Outline: Passport Last name with numbers error validation
    Given User enters data as a <PassportSubject>
    When User clicks on continue
    Then I see the Lastname error in the error summary as Enter your surname as it appears on your passport
    And I see the Lastname error in the error field as Error:Enter your surname as it appears on your passport
    And The test is complete and I close the driver
    Examples:
      |PassportSubject      |
      |InvalidLastNameWithNumbers |

  @Passport_test @build @staging @integration
  Scenario Outline: Passport Last name with special characters error validation
    Given User enters data as a <PassportSubject>
    When User clicks on continue
    Then I see the Lastname error in the error summary as Enter your surname as it appears on your passport
    And I see the Lastname error in the error field as Error:Enter your surname as it appears on your passport
    And The test is complete and I close the driver
    Examples:
      |PassportSubject |
      |InvalidLastNameWithSpecialCharacters |

  @Passport_test @build @staging @integration
  Scenario Outline: Passport No Last name in the Last name field error validation
    Given User enters data as a <PassportSubject>
    When User clicks on continue
    Then I see the Lastname error in the error summary as Enter your surname as it appears on your passport
    And I see the Lastname error in the error field as Error:Enter your surname as it appears on your passport
    And The test is complete and I close the driver
    Examples:
      |PassportSubject |
      |NoLastName |

  @Passport_test @build @staging @integration
  Scenario Outline: Passport First name with numbers error validation
    Given User enters data as a <PassportSubject>
    When User clicks on continue
    Then I see the firstname error summary as Enter your first name as it appears on your passport
    And I see the firstname error in the error field as Error:Enter your first name as it appears on your passport
    And The test is complete and I close the driver
    Examples:
      |PassportSubject      |
      |InvalidFirstNameWithNumbers |

  @Passport_test @build @staging @integration
  Scenario Outline: Passport First name with special characters error validation
    Given User enters data as a <PassportSubject>
    When User clicks on continue
    Then I see the firstname error summary as Enter your first name as it appears on your passport
    And I see the firstname error in the error field as Error:Enter your first name as it appears on your passport
    And The test is complete and I close the driver
    Examples:
      |PassportSubject |
      |InvalidFirstNameWithSpecialCharacters |

  @Passport_test @build @staging @integration
  Scenario Outline: Passport No First name in the First name field error validation
    Given User enters data as a <PassportSubject>
    When User clicks on continue
    Then I see the firstname error summary as Enter your first name as it appears on your passport
    And I see the firstname error in the error field as Error:Enter your first name as it appears on your passport
    And The test is complete and I close the driver
    Examples:
      |PassportSubject |
      |NoFirstName |

  @Passport_test @build @staging @integration
  Scenario Outline: Passport Date of birth that are not real error validation
    Given User enters data as a <PassportSubject>
    When User clicks on continue
    Then I see check date of birth sentence as Enter your date of birth as it appears on your passport
    And I see enter the date as it appears above the field as Error:Enter your date of birth as it appears on your passport
    And The test is complete and I close the driver
    Examples:
      |PassportSubject |
      |InvalidDateOfBirth |

  @Passport_test @build @staging @integration
  Scenario Outline: Passport Date of birth with special characters error validation
    Given User enters data as a <PassportSubject>
    When User clicks on continue
    Then I see check date of birth sentence as Enter your date of birth as it appears on your passport
    And I see enter the date as it appears above the field as Error:Enter your date of birth as it appears on your passport
    And The test is complete and I close the driver
    Examples:
      |PassportSubject |
      |DateOfBirthWithSpecialCharacters |

  @Passport_test @build @staging @integration
  Scenario Outline: Passport Date of birth in the future error validation
    Given User enters data as a <PassportSubject>
    When User clicks on continue
    Then I see check date of birth sentence as Your date of birth must be in the past
    And I see enter the date as it appears above the field as Error:Your date of birth must be in the past
    And The test is complete and I close the driver
    Examples:
      |PassportSubject |
      |DateOfBirthInFuture |

  @Passport_test @build @staging @integration
  Scenario Outline: Passport - No Date in the Date of birth field error validation
    Given User enters data as a <PassportSubject>
    When User clicks on continue
    Then I see check date of birth sentence as Enter your date of birth as it appears on your passport
    And I see enter the date as it appears above the field as Error:Enter your date of birth as it appears on your passport
    And The test is complete and I close the driver
    Examples:
      |PassportSubject |
      |NoDateOfBirth |


  @Passport_test @build @staging @integration
  Scenario Outline: Passport Valid to date that are not real error validation
    Given User enters data as a <PassportSubject>
    When User clicks on continue
    Then I can see the valid to date error in the error summary as Enter the expiry date as it appears on your passport
    And I can see the Valid to date field error as Error:Enter the expiry date as it appears on your passport
    And The test is complete and I close the driver
    Examples:
      |PassportSubject |
      |InvalidValidToDate |

  @Passport_test @build @staging @integration
  Scenario Outline: Passport Valid to date with special characters error validation
    Given User enters data as a <PassportSubject>
    When User clicks on continue
    Then I can see the valid to date error in the error summary as Enter the expiry date as it appears on your passport
    And I can see the Valid to date field error as Error:Enter the expiry date as it appears on your passport
    And The test is complete and I close the driver
    Examples:
      |PassportSubject |
      |ValidToDateWithSpecialCharacters |

  @Passport_test @build @staging @integration
  Scenario Outline: Passport Valid to date in the past error validation
    Given User enters data as a <PassportSubject>
    When User clicks on continue
    Then I can see the valid to date error in the error summary as Your passport must not have expired more than 18 months ago
    And I can see the Valid to date field error as Error:Your passport must not have expired more than 18 months ago
    And The test is complete and I close the driver
    Examples:
      |PassportSubject |
      |ValidToDateInPast |

  @Passport_test @build @staging @integration
  Scenario Outline: Passport - No date in the Valid to date field error validation
    Given User enters data as a <PassportSubject>
    When User clicks on continue
    Then I can see the valid to date error in the error summary as Enter the expiry date as it appears on your passport
    And I can see the Valid to date field error as Error:Enter the expiry date as it appears on your passport
    And The test is complete and I close the driver
    Examples:
      |PassportSubject |
      |NoValidToDate |

  @Passport_test @build @staging @integration
  Scenario Outline: Passport number less than 8 characters error validation
    Given User enters data as a <PassportSubject>
    When User clicks on continue
    Then I see the passport number error in the summary as Your passport number should be 9 digits long
    And I can see the passport number error in the field as Error:Your passport number should be 9 digits long
    And The test is complete and I close the driver
    Examples:
      |PassportSubject |
      |PassportNumLessThan8Char |

  @Passport_test @build @staging @integration
  Scenario Outline: Passport number with special characters and spaces error validation
    Given User enters data as a <PassportSubject>
    When User clicks on continue
    Then I see the passport number error in the summary as Your passport number should not include letters or symbols
    And I can see the passport number error in the field as Error:Your passport number should not include letters or symbols
    And The test is complete and I close the driver
    Examples:
      |PassportSubject |
      |PassportNumberWithSpecialChar |

  @Passport_test @build @staging @integration
  Scenario Outline: Passport number with alpha numeric characters error validation
    Given User enters data as a <PassportSubject>
    When User clicks on continue
    Then I see the passport number error in the summary as Your passport number should not include letters or symbols
    And I can see the passport number error in the field as Error:Your passport number should not include letters or symbols
    And The test is complete and I close the driver
    Examples:
      |PassportSubject |
      |PassportNumberWithNumericChar |

  @Passport_test @build @staging @integration
  Scenario Outline: Passport number with alpha characters error validation
    Given User enters data as a <PassportSubject>
    When User clicks on continue
    Then I see the passport number error in the summary as Your passport number should not include letters or symbols
    And I can see the passport number error in the field as Error:Your passport number should not include letters or symbols
    And The test is complete and I close the driver
    Examples:
      |PassportSubject |
      |PassportNumberWithAlphaChar |

  @Passport_test @build @staging @integration
  Scenario Outline: Passport - No passport number in the passport number field error validation
    Given User enters data as a <PassportSubject>
    When User clicks on continue
    Then I see the passport number error in the summary as Enter the number as it appears on your passport
    And I can see the passport number error in the field as Error:Enter the number as it appears on your passport
    And The test is complete and I close the driver
    Examples:
      |PassportSubject |
      |NoPassportNumber |

  @Passport_test @build @staging @integration @smoke
  Scenario Outline: Passport Generate VC with invalid Passport number and prove in another way unhappy path
    Given User enters data as a <PassportSubject>
    When User clicks on continue
    When User click on ‘prove your identity another way' Link
    And User selects prove another way radio button
    Then I navigate to the passport verifiable issuer to check for a Valid response
    And JSON response should contain documentNumber 887766551 same as given passport
    And The test is complete and I close the driver
    Examples:
      |PassportSubject           |
      | IncorrectPassportNumber     |