package uk.gov.di.ipv.cri.passport.acceptance_tests.step_definitions.stepDefsFromIpvRepo;

import io.cucumber.java.en.And;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo.EnterPassportDetailsPage;

import java.io.IOException;

public class PassportCriSteps {

    private final EnterPassportDetailsPage enterPassportDetailsPage =
            new EnterPassportDetailsPage();

    @When("User {string} adds their passport details")
    public void user_adds_their_passport_details(String PassportSubject) {
        enterPassportDetailsPage.enterPassportCriDetails(
                uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.UtilitiesFromIpvRepo
                        .PassportSubject.valueOf(PassportSubject));
    }

    @Then("proper error message for invalid passport number should be displayed")
    public void properErrorMessageForInvalidPassportNumberShouldBeDisplayed() {
        enterPassportDetailsPage.invalidPassport();
    }

    @Then("proper error message for invalid First Name should be displayed")
    public void properErrorMessageForInvalidFirstNameShouldBeDisplayed() {
        enterPassportDetailsPage.invalidFirstName();
    }

    @Then("proper error message for invalid Surname should be displayed")
    public void properErrorMessageForInvalidSurnameShouldBeDisplayed() {
        enterPassportDetailsPage.invalidsurname();
    }

    @Then("proper error message for invalid Date of Birth should be displayed")
    public void properErrorMessageForInvalidDateOfBirthShouldBeDisplayed() {
        enterPassportDetailsPage.invalidDob();
    }

    @Then("proper error message for invalid Expiry Date should be displayed")
    public void properErrorMessageForInvalidExpiryDateShouldBeDisplayed() {
        enterPassportDetailsPage.invalidExpdate();
    }

    @When("User adds Invalid {string} and then adds valid {string}")
    public void userAddsInvalidAndThenAddsValid(
            String InvalidPassportSubject, String PassportSubject) {
        enterPassportDetailsPage.passportRetry(
                uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.UtilitiesFromIpvRepo
                        .InvalidPassportSubject.valueOf(InvalidPassportSubject),
                uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.UtilitiesFromIpvRepo
                        .PassportSubject.valueOf(PassportSubject));
    }

    @Then("we cannot prove your identity right now error page is displayed")
    public void weCannotProveYourIdentityRightNowErrorPageIsDisplayed() {
        enterPassportDetailsPage.cannotproveidentity();
    }

    @When("User adds Invalid {string} and then adds Invalid {string}")
    public void userAddsInvalidAndThenAddsInvalid(
            String InvalidPassportSubject, String InvalidPassportSubject2) {
        enterPassportDetailsPage.invalidpassportRetry(
                uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.UtilitiesFromIpvRepo
                        .InvalidPassportSubject.valueOf(InvalidPassportSubject),
                uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.UtilitiesFromIpvRepo
                        .InvalidPassportSubject.valueOf(InvalidPassportSubject));
    }

    @When("User adds Invalid {string}")
    public void userAddsInvalid(String InvalidPassportSubject) {
        enterPassportDetailsPage.invalidPassportRetryFirst(
                uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.UtilitiesFromIpvRepo
                        .InvalidPassportSubject.valueOf(InvalidPassportSubject));
    }

    @And("adds again Invalid {string}")
    public void addsAgainInvalid(String InvalidPassportSubject) {
        enterPassportDetailsPage.invalidPassportRetrySecond(
                uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.UtilitiesFromIpvRepo
                        .InvalidPassportSubject.valueOf(InvalidPassportSubject));
    }

    @When("User clicks prove your identity in another way")
    public void userClicksProveYourIdentityInAnotherWay() {
        enterPassportDetailsPage.proveidentityanotherway();
    }

    @When("User clicks Try to Enter Passport details and redirected back to passport page")
    public void userClicksTryToEnterPassportDetailsAndRedirectedBackToPassportPage() {
        enterPassportDetailsPage.proveByPassport();
    }

    @When("User adds Invalid {string} and then adds through retry valid {string}")
    public void userAddsInvalidAndThenAddsThroughRetryValid(
            String InvalidPassportSubject, String PassportSubject) {
        enterPassportDetailsPage.passportRetryth(
                uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.UtilitiesFromIpvRepo
                        .InvalidPassportSubject.valueOf(InvalidPassportSubject),
                uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.UtilitiesFromIpvRepo
                        .PassportSubject.valueOf(PassportSubject));
    }

    @Then("Appropriate {string} response should be displayed")
    public void appropriateResponseShouldBeDisplayed(String jsonResp) throws IOException {
        enterPassportDetailsPage.jsonResp(jsonResp);
    }

    @Then("Appropriate Error {string} response should be displayed")
    public void appropriateErrorResponseShouldBeDisplayed(String jsonResp) throws IOException {
        enterPassportDetailsPage.errorjsonResp(jsonResp);
    }

    @When("user updated cookies can see the stub content in Welsh")
    public void userUpdatedCookiesCanSeeTheStubContentInWelsh() {
        enterPassportDetailsPage.cookieupdatecy();
    }

    @When("user updated cookies can see the non CRI content in Welsh")
    public void userUpdatedCookiesCanSeeTheNonCRIContentInWelsh() {
        enterPassportDetailsPage.updateLanguageCookiesDirect("cy");
    }

    @Then("the content is displayed in Welsh language in GOVUK account page")
    public void theContentIsDisplayedInWelshLanguageInGOVUKAccountPage() {
        enterPassportDetailsPage.weleshLngGOVUKPage();
    }

    @Then("the content is displayed in Welsh language in Passport CRI Page")
    public void theContentIsDisplayedInWelshLanguageInPassportCRIPage() {
        enterPassportDetailsPage.weleshLngPassportPage();
    }

    @Then("proper error message for invalid passport number should be displayed in Welsh")
    public void properErrorMessageForInvalidPassportNumberShouldBeDisplayedInWelsh() {
        enterPassportDetailsPage.weleshErrorInvalidPassport();
    }

    @Then("proper error message for invalid first name should be displayed in Welsh")
    public void properErrorMessageForInvalidFirstNameShouldBeDisplayedInWelsh() {
        enterPassportDetailsPage.weleshErrorInvalidFirstName();
    }

    @Then("proper error message for invalid surname should be displayed in Welsh")
    public void properErrorMessageForInvalidSurnameShouldBeDisplayedInWelsh() {
        enterPassportDetailsPage.weleshErrorInvalidSurName();
    }

    @Then("proper error message for invalid dob should be displayed in Welsh")
    public void properErrorMessageForInvalidDobShouldBeDisplayedInWelsh() {
        enterPassportDetailsPage.weleshErrorInvaliddob();
    }

    @Then("proper error message for invalid exp date should be displayed in Welsh")
    public void properErrorMessageForInvalidExpDateShouldBeDisplayedInWelsh() {
        enterPassportDetailsPage.weleshErrorInvalidexp();
    }

    @Then("we cannot prove your identity right now error page is displayed in Welsh")
    public void weCannotProveYourIdentityRightNowErrorPageIsDisplayedInWelsh() {
        enterPassportDetailsPage.weleshErrorcannotprove();
    }

    @And("the {string} successfully adds their Passport Details")
    public void theSuccessfullyAddsTheirPassportDetails(String PassportSubject) throws IOException {
        enterPassportDetailsPage.enterPassportDetails(PassportSubject);
    }

    @And("user enters the data in Passport stub as a {}")
    public void userEntersTheDataInPassportStubAsAPassportSubject(String PassportSubject)
            throws IOException {
        enterPassportDetailsPage.enterStubPassportDetails(PassportSubject);
    }

    @And("user does not enters the data in Passport stub and click on submit")
    public void userDoesNotEntersTheDataInPassportStubAndClickOnSubmit() {
        enterPassportDetailsPage.enterNoStubPassportDetails();
    }

    @Then("technical error page should be displayed in Welsh")
    public void technicalErrorPageShouldBeDisplayedInWelsh() {
        enterPassportDetailsPage.weleshTechError();
    }

    @Then("user is redirected back to the Passport CRI build Stub")
    public void userIsRedirectedBackToThePassportCRIBuildStub() {
        enterPassportDetailsPage.userIsOnPassportcri();
    }

    @When("User {string} adds their passport details in passport page")
    public void userAddsTheirPassportDetailsInPassportPage(String userName) throws IOException {
        enterPassportDetailsPage.enterPassportCriDetail(userName);
    }

    @And("user clicks on prove identity another way")
    public void userClicksOnProveIdentityAnotherWay() {
        enterPassportDetailsPage.proveidentityanotherway();
    }

    @And("user clicks on continue entering passport details")
    public void userClicksOnContinueEnteringPassportDetails() {
        enterPassportDetailsPage.continueEnteringPassportDetails();
    }

    @Then("Branding changes for GOV.UK One login displayed")
    public void brandingChangesForGOVUKOneLoginDisplayed() {
        enterPassportDetailsPage.oneLoginBrandingChanges();
    }

    @And("user enters the data in Passport stub without JWT Expiry as a {}")
    public void userEntersTheDataInPassportStubWithoutJWTExpiryAsAPassportSubject(
            String PassportSubject) throws IOException {
        enterPassportDetailsPage.enterStubNoExpPassportDetails(PassportSubject);
    }

    @And("user enters the data in Passport stub JWT expired as a {}")
    public void userEntersTheDataInPassportStubJWTExpiredAsAPassportSubject(String PassportSubject)
            throws IOException {
        enterPassportDetailsPage.enterStubExpPassportDetails(PassportSubject);
    }

    @Then("the user should be taken to Passport CRI Page")
    public void theUserShouldBeTakenToPassportCRIPage() {
        enterPassportDetailsPage.userOnPasspoirtCriPage();
    }

    @And("Prove your identity in another way is displayed")
    public void proveYourIdentityInAnotherWayIsDisplayed() {
        enterPassportDetailsPage.proveidentityanother();
    }
}
