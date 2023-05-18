Feature: Passport Test (Through Passport Stub)

  @PYIC-1570a
  Scenario Outline: Passport details stub happy path - <PassportSubject>
    Given I am on Orchestrator Stub
    And I click on Debug route
    And I click on ukPassport
    When User "<PassportSubject>" adds their passport details
    Then Appropriate "<StubValidJsonResponse>" response should be displayed

    Examples:
      | PassportSubject            |  StubValidJsonResponse |
      |PassportSubjectHappyDanny   |  StubValidJsonResponse |
      |PassportSubjectHappyKenneth |  StubValidJsonResponse |
      |PassportSubjectHappySuzie   |  StubValidJsonResponse |
      |PassportSubjectHappySandra  |  StubValidJsonResponse |
      |PassportSubjectHappyBen     |  StubValidJsonResponse |
      |PassportSubjectHappyAlex    |  StubValidJsonResponse |

  @Test
  Scenario Outline: Passport details page unhappy path
    Given I am on Orchestrator Stub
    And I click on Debug route
    And I click on ukPassport
    When User "<PassportSubject>" adds their passport details
    Then proper error message for invalid passport number should be displayed
    Examples:
      | PassportSubject       |
      | InvalidPassportNumber |

  @Test
  Scenario Outline: Invalid First Name
    Given I am on Orchestrator Stub
    And I click on Debug route
    And I click on ukPassport
    When User "<PassportSubject>" adds their passport details
    Then proper error message for invalid First Name should be displayed
    Examples:
      | PassportSubject  |
      | InvalidfirstName |

  @Test
  Scenario Outline: Invalid Surname
    Given I am on Orchestrator Stub
    And I click on Debug route
    And I click on ukPassport
    When User "<PassportSubject>" adds their passport details
    Then proper error message for invalid Surname should be displayed
    Examples:
      | PassportSubject |
      | Invalidsurname  |

  @Test
  Scenario Outline: Invalid Date of Birth
    Given I am on Orchestrator Stub
    And I click on Debug route
    And I click on ukPassport
    When User "<PassportSubject>" adds their passport details
    Then proper error message for invalid Date of Birth should be displayed
    Examples:
      | PassportSubject    |
      | InvalidDateofBirth |

  @Test
  Scenario Outline: Invalid Passport Expiry Date
    Given I am on Orchestrator Stub
    And I click on Debug route
    And I click on ukPassport
    When User "<PassportSubject>" adds their passport details
    Then proper error message for invalid Expiry Date should be displayed
    Examples:
      | PassportSubject   |
      | InvalidExpiryDate |

  @PYIC-1570a
  Scenario Outline: Passport Retry Test Happy Path
    Given I am on Orchestrator Stub
    And I click on Debug route
    And I click on ukPassport
    When User adds Invalid "<InvalidPassportSubject>" and then adds valid "<PassportSubject>"
    Then Appropriate "<StubValidJsonResponse>" response should be displayed
    Examples:
      | InvalidPassportSubject | PassportSubject           | StubValidJsonResponse |
      | PassportSubjectInvalid | PassportSubjectHappyDanny | StubValidJsonResponse |

  @PYIC-1570b
  Scenario Outline: Passport Retry Test Invalid Passport
    Given I am on Orchestrator Stub
    And I click on Debug route
    And I click on ukPassport
    When User adds Invalid "<InvalidPassportSubject>"
    And  adds again Invalid "<InvalidPassportSubject>"
    Then Appropriate Error "<StubErrorJsonResponse>" response should be displayed
    Examples:
      | InvalidPassportSubject | StubErrorJsonResponse |
      | PassportSubjectInvalid | StubErrorJsonResponse |

  @PYIC-1636
  Scenario: Passport Escape route unable to prove identity unhappy path
    Given I am on Orchestrator Stub
    And I click on Debug route
    And I click on ukPassport
    When User clicks prove your identity in another way
    Then we cannot prove your identity right now error page is displayed

  @PYIC-1636
  Scenario Outline: Passport Escape route happy path
    Given I am on Orchestrator Stub
    And I click on Debug route
    And I click on ukPassport
    When User adds Invalid "<InvalidPassportSubject>" and then adds through retry valid "<PassportSubject>"
    Then Appropriate "<StubValidJsonResponse>" response should be displayed

    Examples:
      |InvalidPassportSubject  | PassportSubject           | StubValidJsonResponse |
      |PassportSubjectInvalid  | PassportSubjectHappyDanny | StubValidJsonResponse |

  @PYIC-1636
  Scenario Outline: Passport Escape Route 2nd retry Happy Path
    Given I am on Orchestrator Stub
    And I click on Debug route
    And I click on ukPassport
    When User adds Invalid "<InvalidPassportSubject>"
    And User clicks Try to Enter Passport details and redirected back to passport page
    And  adds again Invalid "<InvalidPassportSubject>"
    Then Appropriate Error "<StubErrorJsonResponse>" response should be displayed

    Examples:
      |InvalidPassportSubject  | StubErrorJsonResponse |
      |PassportSubjectInvalid  | StubErrorJsonResponse |