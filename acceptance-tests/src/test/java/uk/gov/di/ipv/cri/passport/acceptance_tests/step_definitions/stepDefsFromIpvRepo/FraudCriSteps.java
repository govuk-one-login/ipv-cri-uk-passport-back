package uk.gov.di.ipv.cri.passport.acceptance_tests.step_definitions.stepDefsFromIpvRepo;

import io.cucumber.java.en.And;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import org.junit.Assert;
import org.openqa.selenium.By;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo.CheckingYourDetailsPage;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo.FraudCheckStubPage;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo.IpvCheckResultsPage;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo.IpvCoreFrontPageArchive;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.UtilitiesFromIpvRepo.BrowserUtils;

import java.io.IOException;

import static uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.UtilitiesFromIpvRepo.PageObjectSupport.clickElement;

public class FraudCriSteps {

    private final CheckingYourDetailsPage checkingYourDetailsPage = new CheckingYourDetailsPage();
    private static final By SUBMIT_AUTH = By.xpath("//input[@name='submit']");

    @And("the user completes the Fraud Cri Check")
    public void theUserCompletesTheFraudCriCheck() {
        checkingYourDetailsPage.clickContinue();
    }

    @And("user enters data in fraud stub and Click on submit data and generate auth code")
    public void userEntersDataInFraudStubAndClickOnSubmitDataAndGenerateAuthCode() {
        FraudCheckStubPage.enterFraudDetails();
    }

    @Then("user should be successfully validated in {string} full journey")
    public void userShouldBeSuccessfullyValidatedInFullJourney(String jsonResp) throws IOException {
        IpvCheckResultsPage.mobileStubSuccess(jsonResp);
    }

    @Then("user should be on Fraud Check \\(Stub)")
    public void userShouldBeOnFraudCheckStub() {
        BrowserUtils.waitForPageToLoad(10);
        Assert.assertEquals(
                "Fraud Check (Stub)", new IpvCoreFrontPageArchive().FraudStub.getText());
    }

    @When("user Click on submit data and generates auth code")
    public void userClickOnSubmitDataAndGeneratesAuthCode() {
        clickElement(SUBMIT_AUTH);
    }

    @When("user enters data in fraud stub and Click on submit data and generates auth code")
    public void userEntersDataInFraudStubAndClickOnSubmitDataAndGeneratesAuthCode() {
        clickElement(SUBMIT_AUTH);
    }

    @When("user enters data in fraud build stub and Click on submit data and generates auth code")
    public void userEntersDataInFraudBuildStubAndClickOnSubmitDataAndGeneratesAuthCode() {
        FraudCheckStubPage.enterFraudDetails();
    }

    @When(
            "user enters data in fraud build stub without JWT Expiry and Click on submit data and generates auth code")
    public void
            userEntersDataInFraudBuildStubWithoutJWTExpiryAndClickOnSubmitDataAndGeneratesAuthCode() {
        FraudCheckStubPage.enterFraudDetailsWithoutJwtExp();
    }

    @When(
            "user enters data in fraud build stub DVLA and Click on submit data and generates auth code")
    public void userEntersDataInFraudBuildStubDVLAAndClickOnSubmitDataAndGeneratesAuthCode() {
        FraudCheckStubPage.enterFraudDetailsDVLA();
    }

    @When(
            "user enters data in fraud build stub DVA and Click on submit data and generates auth code")
    public void userEntersDataInFraudBuildStubDVAAndClickOnSubmitDataAndGeneratesAuthCode() {
        FraudCheckStubPage.enterFraudDetailsDVA();
    }
}
