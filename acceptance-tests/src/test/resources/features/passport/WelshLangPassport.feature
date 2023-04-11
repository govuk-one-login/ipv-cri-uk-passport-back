Feature: Passport Language Test

  Background: @Language-regression
    Given I navigate to the IPV Core Stub
    And I click the passport CRI for the testEnvironment
    Then I search for passport user number 5 in the Experian table
    And I add a cookie to change the language to Welsh
    And I assert the URL is valid

  @Language-regression
  Scenario: Beta Banner
    Given I view the Beta banner
    When the beta banner reads Mae hwn yn wasanaeth newydd – bydd eich adborth (agor mewn tab newydd) yn ein helpu i’w wella.
    Then The test is complete and I close the driver

  @Language-regression
  Scenario:User Selects landed in the passport page and Validate the title and sentences
    Then I check the page title is Rhowch eich manylion yn union fel maent yn ymddangos ar eich pasbort y DU – Prove your identity – GOV.UK
    And I see the heading Rhowch eich manylion yn union fel maent yn ymddangos ar eich pasbort y DU
    And I see We will check your details as Byddwn yn gwirio eich manylion gydar DVLA i sicrhau nad yw eich pasbort yrru wedi cael ei chanslo na'i hadrodd fel un sydd ar goll neu wedi ei dwyn.
    And I see sentence Os nad oes gennych basbort y DU neu os na allwch gofio’ch manylion, gallwch brofi pwy ydych chi mewn ffordd arall yn lle hynny.
    And The test is complete and I close the driver

  @Language-regression
  Scenario: Name fields
    When I can see the lastname as Cyfenw
    And I can see the givenName as Enwau a roddwyd
    And I can see the middleName as Enwau canol
    And I can see the sentence Gadewch hyn yn wag os nad oes gennych unrhyw enwau canol
    And The test is complete and I close the driver

  @Language-regression
  Scenario: DoB Fields
    When I can see the DoB fields titled Dyddiad geni
    When I can see example as Er enghraifft, 5 9 1973
    Then I can see date as Diwrnod
    And I can see month as Mis
    And I can see year as Blwyddyn
    And The test is complete and I close the driver

  @Language-regression
  Scenario: Valid to date field
    When I can see the Valid to date field titled Dyddiad dod i ben
    And I can see Valid to date sentence as Er enghraifft, 27 5 2029
    Then I can see date as Diwrnod
    And I can see month as Mis
    Then I can see year as Blwyddyn
    And The test is complete and I close the driver

  @Language-regression
  Scenario: passport number
    When I can see the passport number field titled Rhif pasbort
    Then I see the passport number sentence Dyma’r rhif 9 digid yng nghornel dde uchaf y dudalen llun yn eich pasbort
    And The test is complete and I close the driver

  @Language-regression
   Scenario: Passport details Name field error message in Welsh(fail)
     When I enter the invalid last name and first name
     When User clicks on continue
     Then the validation text reads Mae problem
     And I see the Lastname error in the error summary as Rhowch eich cyfenw fel mae’n ymddangos ar eich pasbort
     And I see the firstname error summary as Rhowch eich enw cyntaf fel mae’n ymddangos ar eich pasbort
     And I see the middlenames error summary as Rhowch eich enwau canol fel maent yn ymddangos ar eich pasbort
     And The test is complete and I close the driver

  @Language-regression
  Scenario Outline: Passport details IncorrectDateOfBirth error message in Welsh
    When User clicks on continue
    Then the validation text reads Mae problem
    Then I clear the data and re enter the date of birth
    And  User clicks on continue
    And I see check date of birth sentence as Rhowch y dyddiad dod i ben fel mae’n ymddangos ar eich pasbort
    When User Re-enters data as a <PassportSubject>
    And  User clicks on continue
    Then I see check date of birth sentence as Rhaid i’ch dyddiad geni fod yn y gorffennol
    And The test is complete and I close the driver

    Examples:
      |PassportSubject |
      |DateOfBirthInFuture |


  @Language-regression
  Scenario: Passport Valid until date field error message in Welsh
    When I enter the invalid Valid to date field
    And  User clicks on continue
    And I can see the valid to date error in the error summary as Rhowch y dyddiad dod i ben fel mae’n ymddangos ar eich pasbort
    Then I clear the data and re enter the valid to expired year 
    And  User clicks on continue
    And I can see the valid to date error in the error summary as Mae’n rhaid i’ch pasbort fod heb wedi dod i ben dros 18 mis yn ôl
    And The test is complete and I close the driver

 @Language-regression
  Scenario: passport number field error message in Welsh
    When I enter passport field empty
    Then User clicks on continue
    And I see the passport number error in the summary as Rhowch y rhif fel mae’n ymddangos ar eich pasbort
    And I clear the passport number enter the invalid passport
    Then User clicks on continue
    And I see the passport number error in the summary as Ni ddylai rhif eich pasbort gynnwys llythrennau na symbolau
    Then I clear the passport number and enter passport with Special Char
    Then User clicks on continue
    And I see the passport number error in the summary as Ni ddylai rhif eich pasbort gynnwys llythrennau na symbolau
    And The test is complete and I close the driver

  @Language-regression
  Scenario:User Selects Passport and landed in passport with page and Page title and sub-text
    Then I check the page title is Rhowch eich manylion yn union fel maent yn ymddangos ar eich pasbort y DU – Prove your identity – GOV.UK
    Then I see the heading Rhowch eich manylion yn union fel maent yn ymddangos ar eich pasbort y DU
    And I see sentence Os nad oes gennych basbort y DU neu os na allwch gofio’ch manylion, gallwch brofi pwy ydych chi mewn ffordd arall yn lle hynny.
    And The test is complete and I close the driver

  @Language-regression
  Scenario Outline:Retry message
    When User enters data as a <PassportSubject>
    Then User clicks on continue
    And I can see Check your details as Gwiriwch bod eich manylion yn cyfateb i’r hyn sydd ar eich pasbort y DU
    Then I see error word as Error
    And I see We could not find your details as Nid oeddem yn gallu ddod o hyd i’ch manylion
    And I can see Check your details as Gwiriwch bod eich manylion yn cyfateb i’r hyn sydd ar eich pasbort y DU
    And I see you will not be able to change your details as Ni fyddwch yn gallu newid eich manylion eto os byddwch yn gwneud camgymeriad.
    And The test is complete and I close the driver

    Examples:
      |PassportSubject |
      |IncorrectPassportNumber |

  @Language-regression
  Scenario: Name fields
    When I can see the lastname as Cyfenw
    And I can see the givenName as Enwau a roddwyd
    And I can see the middleName as Enwau canol
    And I can see the sentence Gadewch hyn yn wag os nad oes gennych unrhyw enwau canol
    And The test is complete and I close the driver

  @Language-regression
  Scenario: DoB Field
    When I can see the DoB fields titled Dyddiad geni
    Then I can see example as Er enghraifft, 5 9 1973
    Then I can see date as Diwrnod
    And I can see month as Mis
    And I can see year as Blwyddyn
    And The test is complete and I close the driver

  @Language-regression
  Scenario: Valid until field
    When I can see the Valid to date field titled Dyddiad dod i ben
    And I can see Valid to date sentence as Er enghraifft, 27 5 2029
    Then I can see date as Diwrnod
    And I can see month as Mis
    And I can see year as Blwyddyn
    And The test is complete and I close the driver

  @Language-regression
  Scenario: passport number
    When I can see the passport number field titled Rhif pasbort
    And I see the passport number sentence Dyma’r rhif 9 digid yng nghornel dde uchaf y dudalen llun yn eich pasbort
    And The test is complete and I close the driver

  @Passport_test @build
  Scenario Outline:  Passport details page happy path
    When User enters data as a <PassportSubject>
    Then User clicks on continue
    Then I navigate to the passport verifiable issuer to check for a Valid response
    And JSON payload should contain validity score 2 and strength score 4
    And The test is complete and I close the driver
    Examples:
      |PassportSubject             |
      |PassportSubjectHappyBilly   |

  @Language-regression
  Scenario: passport number field error message in Welsh
    When I enter invalid passport less than 8 char 
    Then User clicks on continue
    And I see the passport number error in the summary as Dylai rhif eich pasbort fod yn 9 digid o hyd
    And I clear the passport number enter the invalid passport
    Then User clicks on continue
    And I see the passport number error in the summary as Ni ddylai rhif eich pasbort gynnwys llythrennau na symbolau
    And The test is complete and I close the driver

  @Language-regression
  Scenario: Passport details Name field error message in Welsh
    When I enter the invalid last name and first name
    When User clicks on continue
    Then the validation text reads Mae problem
    And I see the Lastname error in the error summary as Rhowch eich cyfenw fel mae’n ymddangos ar eich pasbort
    And I see the firstname error summary as Rhowch eich enw cyntaf fel mae’n ymddangos ar eich pasbort
    And I see the middlenames error summary as Rhowch eich enwau canol fel maent yn ymddangos ar eich pasbort
    And The test is complete and I close the driver

  @Language-regression
  Scenario: Passport details IncorrectDateOfBirth error message in Welsh
    When User clicks on continue
    Then the validation text reads Mae problem
    And I see enter the date as it appears above the field as Gwall:Rhowch eich dyddiad geni fel mae’n ymddangos ar eich pasbort
    And I clear the data and re enter the date of birth
    And  User clicks on continue
    Then I see check date of birth sentence as Rhowch y dyddiad dod i ben fel mae’n ymddangos ar eich pasbort
    And The test is complete and I close the driver

  @Language-regression
  Scenario: Passport Valid to date field error message in Welsh
    When I enter the invalid Valid to date field
    And  User clicks on continue
    Then I can see the Valid to date field error as Gwall:Rhowch y dyddiad dod i ben fel mae’n ymddangos ar eich pasbort
    And I clear the data and re enter the valid to expired year 
    Then  User clicks on continue
    And I can see the valid to date error in the error summary as Mae’n rhaid i’ch pasbort fod heb wedi dod i ben dros 18 mis yn ôl
    And The test is complete and I close the driver

  @Language-regression
  Scenario Outline: Error tab title validation
    Then I check the page title is Rhowch eich manylion yn union fel maent yn ymddangos ar eich pasbort y DU – Prove your identity – GOV.UK
    Then User enters data as a <PassportSubject>
    And User clicks on continue
    Then I check the page title is Rhowch eich manylion yn union fel maent yn ymddangos ar eich pasbort y DU – Prove your identity – GOV.UK
    And The test is complete and I close the driver
    Examples:
      |PassportSubject |
      |InvalidDateOfBirth |