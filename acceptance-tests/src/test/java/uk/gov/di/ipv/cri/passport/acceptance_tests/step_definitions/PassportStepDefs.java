package uk.gov.di.ipv.cri.passport.acceptance_tests.step_definitions;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.cucumber.java.en.And;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import org.junit.Assert;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PassportPageObject;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.BrowserUtils;

import java.io.IOException;

public class PassportStepDefs extends PassportPageObject {

    @When("^User enters data as a (.*)$")
    public void user_enters_and(String passportSubjectScenario) {
        userEntersData(passportSubjectScenario);
    }

    @Given("I navigate to the IPV Core Stub")
    public void navigateToStub() {
        navigateToIPVCoreStub();
    }

    @Then("^I search for passport user number (.*) in the Experian table$")
    public void i_search_for_passport_user_number(String number) {
        searchForUATUser(number);
    }

    @And("I assert the URL is valid")
    public void i_assert_the_url_is_valid() {
        passportPageURLValidation();
    }

    @Given("^I check the page title is (.*)$")
    public void i_check_the_page_titled(String pageTitle) {
        assertPageTitle(pageTitle);
    }

    @Then("I can see CTA {string}")
    public void i_can_see_cta(String string) {
        assertCTATextAs(string);
    }

    @Then(
            "^I should on the page Enter your details exactly as they appear on your UK passport$")
    public void i_should_be_on_the_page() {
        assertPageTitle("hello");
    }

    @When("I am directed to the IPV Core routing page")
    public void i_am_directed_to_the_ipv_core_routing_page() {
        assertUserRoutedToIpvCore();
    }

    @And("I validate the URL having access denied")
    public void iValidateTheURLHavingAccessDenied() {
        assertUserRoutedToIpvCoreErrorPage();
    }

    @Then("^I navigate to the passport verifiable issuer to check for a (.*) response$")
    public void i_navigate_to_passport_verifiable_issuer_for_valid_response(
            String validOrInvalid) {
        navigateToPassportResponse(validOrInvalid);
    }

    @And("^JSON response should contain error description (.*) and status code as (.*)$")
    public void errorInJsonResponse(String testErrorDescription, String testStatusCode)
            throws JsonProcessingException {
        jsonErrorResponse(testErrorDescription, testStatusCode);
    }

    @And("I click Go to passport CRI dev button")
    public void i_click_go_to_passport_cri_dev_button() {
        navigateToPassportCRI();
    }

    @Then("^I can see the heading  Sorry, there is a error$")
    public void i_can_see_the_heading_page() {
        validateErrorPageHeading();
    }

    @Given("^I delete the (.*) cookie to get the unexpected error$")
    public void iDeleteTheCookieToGetTheUnexpectedError(String cookieName) {
        BrowserUtils.deleteCookie(cookieName);
    }

    @And("^I click the passport CRI for the testEnvironment$")
    public void navigateToPassportOnTestEnv() {
        navigateToPassportCRIOnTestEnv();
    }

    @Given("I view the Beta banner")
    public void iViewTheBetaBanner() {
        betaBanner();
    }

    @Then("^the beta banner reads (.*)$")
    public void betaBannerContainsText(String expectedText) {
        betaBannerSentence(expectedText);
    }

    @And("^I see the passport Selection sentence starts with (.*)$")
    public void ICanSeeThePageDescriptionAs(String expectedText) throws Throwable {
        assertPageDescription(expectedText);
    }

    @And("^I see the heading (.*)$")
    public void ICanSeeTheHeadingTextAs(String expectedText) {
        assertPageHeading(expectedText);
    }

    @And("^I see We will check your details as (.*)$")
    public void iSeeTheSentenceWeWillCheckYourDetails(String expectedText) {
        assertPageSourceContains(expectedText);
    }

    @And("^I see sentence (.*)$")
    public void ICanSeeProveAnotherWayLinkTextAs(String expectedText) {
        assertProveAnotherWayLinkText(expectedText);
    }

    @And("^I can see Check your details as (.*)$")
    public void ICanSeeTitleAs(String expectedText) {
        assertPageHeading(expectedText);
    }

    @Given("^I can see the lastname as (.*)$")
    public void ICanSeeLastNameLegendAs(String expectedText) {
        assertLastNameLabelText(expectedText);
    }

    @And("^I can see the givenName as (.*)$")
    public void ICanSeeGivenNameLegendAs(String expectedText) {
        assertGivenNameLegendText(expectedText);
    }

    @And("^I can see the firstName as (.*)$")
    public void ICanSeeFirstNameLabelAs(String expectedText) {
        assertGivenNameDescription(expectedText);
    }

    @And("^I can see the middleName as (.*)$")
    public void ICanSeeMiddleNameLabelAs(String expectedText) {
        assertMiddleNameLabelText(expectedText);
    }

    @And("^I can see the first name sentence (.*)$")
    public void ICanSeeTheFirstNameHintAs(String expectedText) {
        assertGivenNameHint(expectedText);
    }

    @And("^I can see the sentence (.*)$")
    public void ICanSeeMiddleNameHintAs(String expectedText) {
        assertMiddleNameHint(expectedText);
    }

    @Given("^I can see the DoB fields titled (.*)$")
    public void ICanSeeDateOfBirthLegendAs(String expectedText) {
        assertDateOfBirthLegendText(expectedText);
    }

    @And("^I can see example as (.*)$")
    public void ICanSeeDateOfBirthHintTextAs(String expectedText) {
        assertDateOfBirthHintText(expectedText);
    }

    @And("^I can see date as (.*)$")
    public void ICanSeeBirthDayAs(String expectedText) {
        assertBirthDayLabelText(expectedText);
    }

    @And("^I can see month as (.*)$")
    public void ICanSeeMonthAs(String expectedText) {
        assertBirthMonthLabelText(expectedText);
    }

    @And("^I can see year as (.*)$")
    public void ICanSeeIssueYearAs(String expectedText) {
        assertBirthYearLabelText(expectedText);
    }

    @And("^I can see Valid to date sentence as (.*)$")
    public void iCanSeeValidToDateSentence(String expectedText) {
        assertValidToHintText(expectedText);
    }

    @Then("^I can see the Valid to date field titled (.*)$")
    public void ICanSeeTheValidToDateFieldAs(String expectedText) {
        assertValidToLegend(expectedText);
    }

    @Given("^I can see the passport number field titled (.*)$")
    public void iSelectedOnThePreviousPage(String expectedText) {
        assertPassportNumberLabelText(expectedText);
    }

    @Then("^I see the passport number sentence (.*)$")
    public void ISeeThePassportNumberSentenceAs(String expectedText) {
        assertPassportNumberHintText(expectedText);
    }

    @When("I enter the invalid last name and first name")
    public void iEnterTheInvalidLastNameAndFirstName() {
        enterInvalidLastAndFirstName();
    }

    @Then("^the validation text reads (.*)$")
    public void theValidationTextReadsMaeProblem(String expectedText) {
        assertErrorSummaryText(expectedText);
    }

    @And("^I see Check your details as (.*)$")
    public void ISeeCheckYourDetailsAs(String expectedText) {
        youWillBeAbleToFindSentence(expectedText);
    }

    @And("^I see We could not find your details as (.*)$")
    public void ISeeWeCouldNotFindYourDetailsAs(String expectedText) {
        assertFirstLineOfUserNotFoundText(expectedText);
    }

    @And("^I see you will not be able to change your details as (.*)$")
    public void ISeeYouWillNotBeAbleToChangeYourDetailsAs(String expectedText) {
        assertPageSourceContains(expectedText);
    }

    @When("I enter the invalid Valid to date field")
    public void iEnterTheInvalidValidToDateField() {
        enterValidToDate("", "", "");
    }

    @Then("I clear the data and re enter the valid to expired year")
    public void iClearTheDataAndReEnterTheValidToExpiredYear() {
        enterValidToDate("23", "03", "2005");
    }

    @When("I enter passport field empty")
    public void iEnterInvalidPassportFieldEmpty() {
        enterPassportNumber("");
    }

    @Then("I clear the passport number and enter passport with Special Char")
    public void iClearThePassportNumberAndEnterPassportWithSpecialChar() {
        enterPassportNumber("@@@@@@@@@@@@@@@@");
    }

    @And("I clear the passport number enter the invalid passport")
    public void iClearThePassportNumber() {
        enterPassportNumber("PARKE610@$112");
    }

    @When("I enter invalid passport less than 8 char")
    public void iEnterInvalidPassportLessThanChar() {
        enterPassportNumber("111106");
    }

    @And("^I see error word as (.*)$")
    public void iSeeErrorWordAsGwall(String expectedText) {
        assertErrorPrefix(expectedText);
    }

    @And("^I can see CTA as (.*)$")
    public void iCanSeeCTAAs(String expectedText) {
        assertCTATextAs(expectedText);
    }

    @When("^User Re-enters data as a (.*)$")
    public void userReInputsDataAsAPassportSubject(String passportSubject) {
        userReEntersDataAsPassportSubject(passportSubject);
    }

    @Then("I clear the data and re enter the date of birth")
    public void iClearTheDataAndReEnterTheDateOfBirth() {
        enterBirthYear("15", "04", "1968");
    }

    @When("User clicks on continue")
    public void user_clicks_on_continue() {
        Continue.click();
    }

    @Then("Proper error message for Could not find your details is displayed")
    public void properErrorMessageForCouldNotFindDetailsIsDisplayed() {
        userNotFoundInThirdPartyErrorIsDisplayed();
    }

    @And("^I see check date of birth sentence as (.*)$")
    public void ISeeCheckDateOfBirthInErrorSummaryAs(
            String expectedText) {
        assertInvalidDoBInErrorSummary(expectedText);
    }

    @Then("^I see enter the date as it appears above the field as (.*)$")
    public void fieldErrorMessageForNoDOBIsDisplayed(String expectedText) {
        assertInvalidDoBOnField(expectedText);
    }

    @Then("^I can see the valid to date error in the error summary as (.*)$")
    public void properErrorMessageForInvalidValidToDateIsDisplayed(String expectedText) {
        assertInvalidValidToDateInErrorSummary(expectedText);
    }

    @Then("^I can see the Valid to date field error as (.*)$")
    public void fieldErrorMessageForInvalidValidToDateIsDisplayed(String expectedText) {
        assertInvalidValidToDateOnField(expectedText);
    }

    @Then("^I see the passport number error in the summary as (.*)$")
    public void shortPassportNumberErrorMessageIsDisplayed(String expectedText) {
        assertInvalidPassportNumberInErrorSummary(expectedText);
    }

    @Then("^I can see the passport number error in the field as (.*)$")
    public void shortPassportNumberFieldErrorMessageIsDisplayed(String expectedText) {
        assertInvalidPassportNumberOnField(expectedText);
    }

    @Then("^I see the Lastname error in the error summary as (.*)$")
    public void properErrorMessageForInvalidLastNameIsDisplayed(String expectedText) {
        assertInvalidLastNameInErrorSummary(expectedText);
    }

    @Then("^I see the Lastname error in the error field as (.*)$")
    public void fieldErrorMessageForInvalidLastNameIsDisplayed(String expectedText) {
        assertInvalidLastNameOnField(expectedText);
    }

    @Then("^I see the firstname error summary as (.*)$")
    public void properErrorMessageForInvalidFirstNameIsDisplayed(String expectedText) {
        assertInvalidFirstNameInErrorSummary(expectedText);
    }

    @Then("^I see the firstname error in the error field as (.*)$")
    public void fieldErrorMessageForInvalidFirstNameIsDisplayed(String expectedText) {
        assertInvalidFirstNameOnField(expectedText);
    }

    @Then("^I see the middlenames error summary as (.*)")
    public void properErrorMessageForInvalidMiddleNamesIsDisplayed(String expectedText) {
        assertInvalidMiddleNameInErrorSummary(expectedText);
    }

    @Then("^I see the middlenames error in the error field as (.*)$")
    public void fieldErrorMessageForInvalidMiddleNamesIsDisplayed(String expectedText) {
        assertInvalidMiddleNameOnField(expectedText);
    }

    @Given("User enters invalid passport details")
    public void userInputsInvalidPassportDetails() {
        userEntersInvalidPassportDetails();
    }

    @Given("User click on ‘prove your identity another way' Link")
    public void userClickOnProveYourIdentityAnotherWayLink() {
        proveAnotherWay.click();
    }

    @Given("User selects prove another way radio button")
    public void userClickOnProveYourIdentityAnotherWayRadio() {
        proveAnotherWayRadio.click();
        Continue.click();
    }

    @Then(
            "I should be on `Enter your details exactly as they appear on your UK passport` page")
    public void
    i_should_be_on_enter_your_details_exactly_as_they_appear_on_your_uk_passport_page() {
        Assert.assertTrue(passportNumber.isDisplayed());
    }

    @And("^JSON payload should contain ci (.*), validity score (.*) and strength score (.*)$")
    public void contraIndicatorInVerifiableCredential(
            String ci, String validityScore, String strengthScore) throws IOException {
        ciInVC(ci);
        checkScoreInStubIs(validityScore, strengthScore);
    }

    @And("^JSON payload should contain validity score (.*) and strength score (.*)$")
    public void scoresInVerifiableCredential(String validityScore, String strengthScore)
            throws IOException {
        checkScoreInStubIs(validityScore, strengthScore);
    }

    @Given("User click on ‘Back' Link")
    public void userClickOnBackLink() {
        back.click();
    }

    @And("^JSON response should contain documentNumber (.*) same as given passport$")
    public void errorInJsonResponse(String documentNumber) throws IOException {
        assertDocumentNumberInVc(documentNumber);
    }
}
