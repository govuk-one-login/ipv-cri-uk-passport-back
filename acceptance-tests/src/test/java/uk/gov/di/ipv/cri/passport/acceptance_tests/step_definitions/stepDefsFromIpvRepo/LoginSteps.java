package uk.gov.di.ipv.cri.passport.acceptance_tests.step_definitions.stepDefsFromIpvRepo;

import io.cucumber.java.en.And;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import org.junit.Assert;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo.*;
import uk.gov.di.ipv.cri.passport.acceptance_tests.service.ConfigurationService;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.Driver;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.UtilitiesFromIpvRepo.BrowserUtils;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.UtilitiesFromIpvRepo.ConfigurationReader;

import java.security.NoSuchAlgorithmException;
import java.util.logging.Logger;

public class LoginSteps {

    private final ProveYourIdentityGovUkPage proveYourIdentityGovUkPage =
            new ProveYourIdentityGovUkPage();
    private final DeviceSelectionPage deviceSelectionPage = new DeviceSelectionPage();
    private final PassportDocCheckPage passportDocCheckPage = new PassportDocCheckPage();
    private final ConfigurationService configurationService =
            new ConfigurationService(System.getenv("ENVIRONMENT"));
    private static final Logger LOGGER = Logger.getLogger(LoginSteps.class.getName());

    @Given("User on Orchestrator Stub and click on full journey route")
    public void userOnOrchestratorStubAndClickOnFullJourneyRoute() throws NoSuchAlgorithmException {
        Driver.get().get(configurationService.getOrchestratorStubUrl());
        BrowserUtils.waitForPageToLoad(10);
        proveYourIdentityGovUkPage.generateRandomUserId();
        proveYourIdentityGovUkPage.inputuserId();
        proveYourIdentityGovUkPage.fullJourneyRoute();
    }

    @And("clicks continue on the signed into your GOV.UK One Login page")
    public void clicksContinueOnTheSignedIntoYourGOVUKOneLoginPage() {
        proveYourIdentityGovUkPage.waitForPageToLoad();
        proveYourIdentityGovUkPage.ContinueToEnterPassport();
        try {
            if (deviceSelectionPage.isDeviceSelectionScreenPresent()) {
                deviceSelectionPage.selectNoMobileDeviceAndContinue();
                deviceSelectionPage.selectNoIphoneOrAndroidAndContinue();
            }
        } catch (NullPointerException e) {
            LOGGER.warning(
                    "No environment variable specified, please specify a variable for runs in Integration");
        }
        passportDocCheckPage.waitForPageToLoad();
        passportDocCheckPage.passportDocCheck();
    }

    @And("clicks continue on the signed into your GOV.UK account page")
    public void clicksContinueOnTheSignedIntoYourGOVUKAccountPage() {
        proveYourIdentityGovUkPage.waitForPageToLoad();
        proveYourIdentityGovUkPage.ContinueToEnterPassport();
        try {
            if (deviceSelectionPage.isDeviceSelectionScreenPresent()) {
                deviceSelectionPage.selectNoMobileDeviceAndContinue();
                deviceSelectionPage.selectNoIphoneOrAndroidAndContinue();
            }
        } catch (NullPointerException e) {
            LOGGER.warning(
                    "No environment variable specified, please specify a variable for runs in Integration");
        }
        passportDocCheckPage.waitForPageToLoad();
        passportDocCheckPage.passportDocCheck();
    }

    @When("the User navigates to the `Orchestrator Stub` page")
    public void theUserNavigatesToTheOrchestratorStubPage() {
        Driver.get().get(configurationService.getOrchestratorStubUrl());
        BrowserUtils.waitForPageToLoad(5);
    }

    @And("the user signs back in with the same userId")
    public void theUserSignsBackInWithTheSameUserId() {
        proveYourIdentityGovUkPage.inputuserId();
        proveYourIdentityGovUkPage.fullJourneyRoute();
        proveYourIdentityGovUkPage.ContinueToEnterPassport();
    }

    @And("clicks continue on the signed into your GOV.UK One Login page in build stub")
    public void clicksContinueOnTheSignedIntoYourGOVUKOneLoginPageInBuildStub() {
        proveYourIdentityGovUkPage.waitForPageToLoad();
        proveYourIdentityGovUkPage.ContinueToEnterPassport();
        //        passportDocCheckPage.waitForPageToLoad();
        passportDocCheckPage.checkinAppStub();
        passportDocCheckPage.generateOAuthError();
        passportDocCheckPage.passportDocCheck();
    }

    @And("User clicks on Sign-out button")
    public void userClicksOnSignOutButton() {
        proveYourIdentityGovUkPage.clickSignOut();
    }

    @Then("Standard Sign-out page should be displayed")
    public void standardSignOutPageShouldBeDisplayed() {
        proveYourIdentityGovUkPage.signOutPage();
    }

    @And("clicks continue on the signed into your GOV.UK One Login page for Axe test")
    public void clicksContinueOnTheSignedIntoYourGOVUKOneLoginPageForAxeTest() {
        proveYourIdentityGovUkPage.waitForPageToLoad();
        try {
            if (deviceSelectionPage.isDeviceSelectionScreenPresent()) {
                deviceSelectionPage.selectNoMobileDeviceAndContinue();
                deviceSelectionPage.selectNoIphoneOrAndroidAndContinue();
            }
        } catch (NullPointerException e) {
            LOGGER.warning(
                    "No environment variable specified, please specify a variable for runs in Integration");
        }
    }

    @And("User lands on IPVCore identity start page")
    public void userLandsOnIPVCoreIdentityStartPage() {
        Assert.assertEquals(
                "Start proving your identity with GOV.UK One Login",
                new IpvCoreFrontPageArchive().journeycomplete.getText());
    }

    @Given("User on Orchestrator Stub and click on error journey route")
    public void userOnOrchestratorStubAndClickOnErrorJourneyRoute() {
        Driver.get().get(ConfigurationReader.getOrchestratorUrl());
        BrowserUtils.waitForPageToLoad(10);
        proveYourIdentityGovUkPage.errorJourneyRoute();
    }

    @When("unrecoverable error page should be displayed")
    public void unrecoverableErrorPageShouldBeDisplayed() {
        Assert.assertEquals(
                "Sorry, there is a problem",
                new IpvCoreFrontPageArchive().journeycomplete.getText());
    }
}
