package uk.gov.di.ipv.cri.passport.acceptance_tests.step_definitions.stepDefsFromIpvRepo.Archive;

import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import org.junit.Assert;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo.Archive.CoreStubCrisPage;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo.Archive.CoreStubUserSearchPage;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo.CoreStubVerifiableCredentialsPage;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo.EnterPassportDetailsPage;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo.IpvCoreFrontPageArchive;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo.PassportPage;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.Driver;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.UtilitiesFromIpvRepo.BrowserUtils;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.UtilitiesFromIpvRepo.ConfigurationReader;

import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class PassportCriSmokeSteps {

    private final EnterPassportDetailsPage enterPassportDetailsPage =
            new EnterPassportDetailsPage();

    public static final String EXPIRY_MONTH = "10";
    public static final String EXPIRY_YEAR = "2042";
    private static final String PASSPORT_NUMBER = "321654987";
    public static final String SURNAME = "DECERQUEIRA";
    public static final String FIRST_NAME = "KENNETH";
    public static final String BIRTH_DAY = "08";
    public static final String BIRTH_MONTH = "07";
    public static final String BIRTH_YEAR = "1965";
    public static final String EXPIRY_DAY = "01";

    @When("I start at the core stub")
    public void startCoreStub() {
        Driver.get().get(ConfigurationReader.getCoreStubUrl());
        BrowserUtils.waitForPageToLoad(10);
    }

    @When("I click on Build Passport")
    public void clickOnBuildPassport() {
        new CoreStubCrisPage().BuildPassportLink.click();
        BrowserUtils.waitForPageToLoad(10);
    }

    @When("I enter '{}' in the Row Number box")
    public void enterRowNumber(String rowNumber) {
        new CoreStubUserSearchPage().rowNumberBox.sendKeys(rowNumber);
    }

    @When("I click on Go to Build Passport")
    public void clickOnGoToBuildPassport() {
        new CoreStubUserSearchPage().goToBuildPassportButton.click();
        BrowserUtils.waitForPageToLoad(10);
    }

    @Then("I should be on the passport details page")
    public void passportDetailsConfirm() {
        assertTrue(Driver.get().getCurrentUrl().endsWith("/passport/details"));
    }

    @When("I click on ukPassport")
    public void clickOnUkPassport() {
        new IpvCoreFrontPageArchive().UkPassport.click();
        BrowserUtils.waitForPageToLoad(10);
    }

    @When("I fill in my details")
    public void fillInPassportDetails() {
        PassportPage passportPage = new PassportPage();

        passportPage.PassportNumber.sendKeys(PASSPORT_NUMBER);
        passportPage.Surname.sendKeys(SURNAME);
        passportPage.FirstName.sendKeys(FIRST_NAME);
        passportPage.birthDay.sendKeys(BIRTH_DAY);
        passportPage.birthMonth.sendKeys(BIRTH_MONTH);
        passportPage.birthYear.sendKeys(BIRTH_YEAR);
        passportPage.PassportExpiryDay.sendKeys(EXPIRY_DAY);
        passportPage.PassportExpiryMonth.sendKeys(EXPIRY_MONTH);
        passportPage.PassportExpiryYear.sendKeys(EXPIRY_YEAR);
    }

    @Then("I should be on the core stub Verifiable Credentials page")
    public void coreStubVcPageConfirm() {
        assertEquals(
                "Verifiable Credentials", new CoreStubVerifiableCredentialsPage().h1.getText());
    }

    @Then("I should see passport data in JSON")
    public void seePassportData() {
        CoreStubVerifiableCredentialsPage coreStubVerifiableCredentialsPage =
                new CoreStubVerifiableCredentialsPage();
        coreStubVerifiableCredentialsPage.response.click();

        String payload = coreStubVerifiableCredentialsPage.jsonData.getText();
        System.out.println("payload = " + payload);

        Assert.assertTrue(payload.contains(PASSPORT_NUMBER));
        Assert.assertTrue(payload.contains(SURNAME));
        Assert.assertTrue(payload.contains(FIRST_NAME));
        Assert.assertTrue(payload.contains(BIRTH_DAY));
        Assert.assertTrue(payload.contains(BIRTH_MONTH));
        Assert.assertTrue(payload.contains(BIRTH_YEAR));
        Assert.assertTrue(payload.contains(EXPIRY_DAY));
        Assert.assertTrue(payload.contains(EXPIRY_MONTH));
        Assert.assertTrue(payload.contains(EXPIRY_YEAR));
    }

    @When("user clicks on browser back button")
    public void userClicksOnBrowserBackButton() {
        enterPassportDetailsPage.clickBrowserButton();
    }

    @Then("user is redirected back to the Passport CRI Stub")
    public void userIsRedirectedBackToThePassportCRIStub() {
        enterPassportDetailsPage.userIsOnPassportcris();
    }

    @When("user Click on submit data and generate auth code")
    public void userClickOnSubmitDataAndGenerateAuthCode() {
        enterPassportDetailsPage.clickOnlySubAuths();
    }

    @Then("User should see sorry you cannot go back error page")
    public void userShouldSeeSorryYouCannotGoBackErrorPage() {
        enterPassportDetailsPage.backButtonErrPage();
    }

    @Then("User should see error recovery page and clicks on continue")
    public void userShouldSeeErrorRecoveryPageAndClicksOnContinue() {
        enterPassportDetailsPage.backButtonErrPage();
    }

    @Then("user is redirected back to the address CRI Stub")
    public void userIsRedirectedBackToTheAddressCRIStub() {
        enterPassportDetailsPage.userIsOnAddresscri();
    }

    @Then("User should be on KBV \\(Stub)")
    public void userShouldBeOnKBVStub() {
        enterPassportDetailsPage.userIsOnKbvcri();
    }

    @Then("user is redirected back to the fraud CRI Stub")
    public void userIsRedirectedBackToTheFraudCRIStub() {
        enterPassportDetailsPage.userIsOnFraudcri();
    }
}
