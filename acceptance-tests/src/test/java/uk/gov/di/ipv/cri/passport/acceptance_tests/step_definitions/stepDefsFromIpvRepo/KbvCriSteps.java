package uk.gov.di.ipv.cri.passport.acceptance_tests.step_definitions.stepDefsFromIpvRepo;

import io.cucumber.java.en.And;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import org.junit.Assert;
import org.openqa.selenium.By;
import org.openqa.selenium.support.ui.Select;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo.*;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.Driver;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.UtilitiesFromIpvRepo.BrowserUtils;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.UtilitiesFromIpvRepo.ConfigurationReader;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.fail;
import static uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.UtilitiesFromIpvRepo.PageObjectSupport.clickElement;

public class KbvCriSteps {

    private final IpvCoreStubHomepage ipvCoreStubHomepage = new IpvCoreStubHomepage();
    private final VisitCredentialIssuersPage visitCredentialIssuersPage =
            new VisitCredentialIssuersPage();
    private final UserForKbvCriPage userForKbvCriPage = new UserForKbvCriPage();
    private final ExperianUserSearchResultsPage experianUserSearchResultsPage =
            new ExperianUserSearchResultsPage();
    private final KbvQuestionPage kbvQuestionPage = new KbvQuestionPage();
    private final KbvCriResponsePage kbvCriResponsePage = new KbvCriResponsePage();
    private final AnswerSecurityQuestionPage answerSecurityQuestionPage =
            new AnswerSecurityQuestionPage();
    private final String SUCCESSFULLY = "Successfully";
    private final String UNSUCCESSFULLY = "Unsuccessfully";
    private static final By JWT_CHECK_BOX = By.cssSelector("#vcExpiryFlg");
    private static final By CONTINUE_BUTTON = By.xpath("//button[@name='submitButton']");

    @Given("the user is on KBV CRI Stub as {string}")
    public void theUserIsOnKBVCRIStagingAs(String userName) {
        Driver.get().get(ConfigurationReader.getIPVCoreStubUrl());
        ipvCoreStubHomepage.clickVisitCredentialIssuers();
        visitCredentialIssuersPage.visitKbvCredentialIssuer();
        userForKbvCriPage.isUserOnKbvCriPage();
        userForKbvCriPage.enterUsernameAndSearch(userName);
        experianUserSearchResultsPage.goToKbvCri();
    }

    @When("the user answers their KBV Question {string} for {string}")
    public void theUserAnswersTheirKBVQuestionSuccessfully(String answerType, String userName)
            throws IOException {
        kbvQuestionPage.answerKbvQuestion(answerType, userName);
    }

    @Then("the user should see a {string} of {int} in the KBV CRI Response")
    public void theUserShouldSeeAOfInTheKBVCRIResponse(String attribute, int expectedValue) {
        kbvCriResponsePage.clickKbvResponseLink();
        Assert.assertEquals(
                "The "
                        + attribute
                        + " value was not returned correctly. Expected: "
                        + expectedValue
                        + ". Actual: "
                        + kbvCriResponsePage.getKbvCriAttribute(attribute),
                expectedValue,
                kbvCriResponsePage.getKbvCriAttribute(attribute));
    }

    @And("the user {string} {string} Answers {int} KBV CRI Questions")
    public void theUserSuccessfullyAnswersKBVCRIQuestions(
            String userName, String answerType, int correctAnswers) throws IOException {
        answerSecurityQuestionPage.clickContinue();
        for (int i = 0; i < correctAnswers; i++) {
            kbvQuestionPage.answerKbvQuestion(answerType, userName);
        }
    }

    @And("the user {string} {string} passes the KBV CRI Check")
    public void theUserSuccessfullyPassesKBVCRICheck(String userName, String kbvQuestionSuccess)
            throws IOException {
        answerSecurityQuestionPage.clickContinue();
        if (kbvQuestionSuccess.equals(SUCCESSFULLY)) {
            int SUCCESSFUL_KBV_QUESTION_COUNT = 3;
            for (int i = 0; i < SUCCESSFUL_KBV_QUESTION_COUNT; i++) {
                kbvQuestionPage.answerKbvQuestion(kbvQuestionSuccess, userName);
            }
        } else if (kbvQuestionSuccess.equals(UNSUCCESSFULLY)) {
            int UNSUCCESSFUL_KBV_QUESTION_COUNT = 2;
            for (int i = 0; i < UNSUCCESSFUL_KBV_QUESTION_COUNT; i++) {
                kbvQuestionPage.answerKbvQuestion(kbvQuestionSuccess, userName);
            }
        } else {
            fail(
                    "Valid KBV Option not selected in BDD Statement. Possible Values: Successfully, Unsuccessfully");
        }
    }

    private final IpvCheckResultsPage ipvCheckResultsPage = new IpvCheckResultsPage();
    private final UserInfomationPage userInfomationPage = new UserInfomationPage();

    @Then("the user should see that they have {string} proved their identity")
    public void theUserShouldSeeThatTheyHaveProvedTheirIdentity(String identityValidity)
            throws InterruptedException {
        ipvCheckResultsPage.validateIpvCheckResults(identityValidity);
        if (identityValidity.equals(SUCCESSFULLY)) {
            ipvCheckResultsPage.clickContinue();
            userInfomationPage.waitForPageToLoad();
            userInfomationPage.validateCoreIdentityClaim();
            userInfomationPage.validateAddressClaim();
            userInfomationPage.validatePassportClaim();
        }
    }

    @And("user enters data in KBV stub and Click on submit data and generate auth code")
    public void userEntersDataInKBVStubAndClickOnSubmitDataAndGenerateAuthCode() {
        userForKbvCriPage.updateKBVCriStub();
    }

    @Then("user should be unsuccessfully validated in {string} full journey liveness")
    public void userShouldBeUnsuccessfullyValidatedInFullJourneyLiveness(String jsonResp)
            throws IOException {
        IpvCheckResultsPage.mobileStublivenessSuccess(jsonResp);
    }

    @Then("user should be successfully validated in {string} full journey for passport")
    public void userShouldBeSuccessfullyValidatedInFullJourneyForPassport(String jsonResp)
            throws IOException {
        IpvCheckResultsPage.mobileAccessDeniedPassportSuccess(jsonResp);
    }

    @Then("User should be on KBV page and click continue")
    public void userShouldBeOnKBVPageAndClickContinue() {
        BrowserUtils.waitForPageToLoad(10);
        Assert.assertEquals(
                "Answer security questions", new IpvCoreFrontPageArchive().Kbvheader.getText());
        new PassportPage().Continue.click();
    }

    @When("user enters data in kbv stub and Click on submit data and generate auth code")
    public void userEntersDataInKbvStubAndClickOnSubmitDataAndGenerateAuthCode() {
        Select select = new Select(new IpvCoreFrontPageArchive().SelectkbvCRIData);
        select.selectByValue("Kenneth Decerqueira (Valid Experian) KBV");
        new IpvCoreFrontPageArchive().kbvscore.sendKeys("2");
        new PassportPage().SelectCRIData.click();
        clickElement(JWT_CHECK_BOX);
        new IpvCoreFrontPageArchive().JWT_EXP_HR.clear();
        new IpvCoreFrontPageArchive().JWT_EXP_HR.sendKeys("4");
        BrowserUtils.waitForPageToLoad(10);
        new PassportPage().submitdatagenerateauth.click();
    }

    @Then("user should be successful in proving identity")
    public void userShouldBeSuccessfulInProvingIdentity() {
        Assert.assertEquals(
                "Continue to the service you want to use",
                new IpvCoreFrontPageArchive().journeycomplete.getText());
    }

    @Then("user should be successful in proving identity in Welsh")
    public void userShouldBeSuccessfulInProvingIdentityInWelsh() {
        Assert.assertEquals(
                "Parhau i’r gwasanaeth rydych am ei ddefnyddio",
                new IpvCoreFrontPageArchive().journeycomplete.getText());
    }

    @And("the user should be redirected back and seen their that {string} proved")
    public void theUserShouldBeRedirectedBackAndSeenTheirThatProved(String identityValidity)
            throws InterruptedException {
        ipvCheckResultsPage.validateIpvCheckResults(identityValidity);
    }

    @Then("User should be on KBV page")
    public void userShouldBeOnKBVPage() {
        BrowserUtils.waitForPageToLoad(10);
        Assert.assertEquals(
                "Answer security questions", new IpvCoreFrontPageArchive().Kbvheader.getText());
    }

    @When("user clicks on browser back button on KBV Stub")
    public void userClicksOnBrowserBackButtonOnKBVStub() {
        userForKbvCriPage.clickBrowserButton();
        userForKbvCriPage.clickBrowserButton();
    }

    @When(
            "user enters data in kbv stub without JWT Expiry and Click on submit data and generate auth code")
    public void userEntersDataInKbvStubWithoutJWTExpiryAndClickOnSubmitDataAndGenerateAuthCode() {
        Select select = new Select(new IpvCoreFrontPageArchive().SelectkbvCRIData);
        select.selectByValue("Kenneth Decerqueira (Valid Experian) KBV");
        new IpvCoreFrontPageArchive().kbvscore.sendKeys("2");
        new PassportPage().SelectCRIData.click();
        BrowserUtils.waitForPageToLoad(10);
        new PassportPage().submitdatagenerateauth.click();
    }

    @And("User should be able to see the json response page")
    public void userShouldBeAbleToSeeTheJsonResponsePage() {
        clickElement(CONTINUE_BUTTON);
        Assert.assertEquals(
                "Raw User Info Object", new IpvCoreFrontPageArchive().RAW_JSON.getText());
    }

    @When("user enters data in kbv stub for KBV Thin and Click on submit data and generate auth code")
    public void userEntersDataInKbvStubForKBVThinAndClickOnSubmitDataAndGenerateAuthCode() {
        Select select = new Select(new IpvCoreFrontPageArchive().SelectkbvCRIData);
        select.selectByValue("Kenneth Decerqueira (Valid Experian) KBV");
        new IpvCoreFrontPageArchive().kbvscore.sendKeys("0");
        new PassportPage().SelectCRIData.click();
        BrowserUtils.waitForPageToLoad(10);
        new PassportPage().submitdatagenerateauth.click();
    }

    @Then("KBV Thin Error Page should be displayed")
    public void kbvThinErrorPageShouldBeDisplayed() {
        Assert.assertEquals("You need to prove your identity another way",new IpvCoreFrontPageArchive().Kbvheader.getText());
    }

    @When("user enters data in kbv stub for KBV fail and Click on submit data and generate auth code")
    public void userEntersDataInKbvStubForKBVFailAndClickOnSubmitDataAndGenerateAuthCode() {
        Select select = new Select(new IpvCoreFrontPageArchive().SelectkbvCRIData);
        select.selectByValue("Kenneth Decerqueira (Valid Experian) KBV");
        new IpvCoreFrontPageArchive().kbvscore.sendKeys("2");
        new PassportPage().SelectCRIData.click();
        new IpvCoreFrontPageArchive().updateci.sendKeys("D02");
        BrowserUtils.waitForPageToLoad(10);
        new PassportPage().submitdatagenerateauth.click();
    }

    @Then("KBV fail Error Page should be displayed")
    public void kbvFailErrorPageShouldBeDisplayed() {
        Assert.assertEquals("Sorry, we cannot prove your identity",new IpvCoreFrontPageArchive().Kbvheader.getText());
    }
}
