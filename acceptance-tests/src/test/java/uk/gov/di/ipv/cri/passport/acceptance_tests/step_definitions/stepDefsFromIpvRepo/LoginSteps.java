package uk.gov.di.ipv.cri.passport.acceptance_tests.step_definitions.stepDefsFromIpvRepo;

import io.cucumber.java.en.And;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import org.openqa.selenium.By;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo.DeviceSelectionPage;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo.PassportDocCheckPage;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo.ProveYourIdentityGovUkPage;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo.driverLicenceDocCheckPage;
import uk.gov.di.ipv.cri.passport.acceptance_tests.service.ConfigurationService;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.Driver;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.UtilitiesFromIpvRepo.BrowserUtils;

import java.security.NoSuchAlgorithmException;
import java.util.logging.Logger;

import static uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.UtilitiesFromIpvRepo.PageObjectSupport.clickElement;

public class LoginSteps {

    private static final By SELECT_USER_ID = By.cssSelector("#userIdSelect");
    private static final By MOBILE_APP_USER_ID_OPTION =
            By.xpath("//*[@id=\"userIdSelect\"]/option[2]");

    private final ProveYourIdentityGovUkPage proveYourIdentityGovUkPage =
            new ProveYourIdentityGovUkPage();
    private final DeviceSelectionPage deviceSelectionPage = new DeviceSelectionPage();
    private final PassportDocCheckPage passportDocCheckPage = new PassportDocCheckPage();
    private final ConfigurationService configurationService =
            new ConfigurationService(System.getenv("ENVIRONMENT"));
    private final uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo
                    .driverLicenceDocCheckPage
            driverLicenceDocCheckPage = new driverLicenceDocCheckPage();
    private static final Logger LOGGER = Logger.getLogger(LoginSteps.class.getName());

    @Given("User on Orchestrator Stub and click on full journey route")
    public void userOnOrchestratorStubAndClickOnFullJourneyRoute() throws NoSuchAlgorithmException {
        Driver.get().get(configurationService.getOrchestratorStubUrl());
        BrowserUtils.waitForPageToLoad(10);
        proveYourIdentityGovUkPage.generateRandomUserId();
        proveYourIdentityGovUkPage.inputuserId();
        proveYourIdentityGovUkPage.fullJourneyRoute();
    }

    @Given("User on Orchestrator Stub and click on Debug journey route")
    public void userOnOrchestratorStubAndClickOnDebugJourneyRoute()
            throws NoSuchAlgorithmException {
        Driver.get().get(configurationService.getOrchestratorStubUrl());
        BrowserUtils.waitForPageToLoad(10);
        proveYourIdentityGovUkPage.generateRandomUserId();
        proveYourIdentityGovUkPage.inputuserId();
        proveYourIdentityGovUkPage.debugRoute();
    }

    @Then("user should be redirected to user information")
    public void userShouldBeRedirectedToUserInformation() {
        proveYourIdentityGovUkPage.userInfo();
    }

    @Given("User on Orchestrator Stub click on debug route and Doc checking Stub")
    public void userOnOrchestratorStubClickOnDebugRouteAndDocCheckingStub() {
        Driver.get().get(configurationService.getOrchestratorStubUrl());
        BrowserUtils.waitForPageToLoad(10);
        proveYourIdentityGovUkPage.debugRouteMobile();
    }

    @Given("User on build Orchestrator Stub and click on full journey route for mobile app")
    public void userOnBuildOrchestratorStubAndClickOnFullJourneyRouteForMobileApp() {
        Driver.get().get(configurationService.getOrchestratorStubUrl());
        BrowserUtils.waitForPageToLoad(10);
        clickElement(MOBILE_APP_USER_ID_OPTION);
        proveYourIdentityGovUkPage.fullJourneyRouteBuild();
    }

    @Given("User on Orchestrator Stub and click on debug route and then click Passport CRI")
    public void userOnOrchestratorStubAndClickOnDebugRouteAndThenClickPassportCRI() {
        Driver.get().get(configurationService.getOrchestratorStubUrl());
        BrowserUtils.waitForPageToLoad(10);
        proveYourIdentityGovUkPage.debugRoute();
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

    @Given("User on Orchestrator Stub and click on full journey route for account deletion")
    public void userOnOrchestratorStubAndClickOnFullJourneyRouteForAccountDeletion()
            throws NoSuchAlgorithmException {
        Driver.get().get(configurationService.getOrchestratorStubUrl());
        BrowserUtils.waitForPageToLoad(30);
        proveYourIdentityGovUkPage.generateRandomUserId();
        proveYourIdentityGovUkPage.inputuserId();
        proveYourIdentityGovUkPage.fullJourneyRoute();
    }

    @And("the users account is deleted in SNS topic")
    public void theUsersAccountIsDeletedInSNSTopic() {
        proveYourIdentityGovUkPage.callSnsTopic();
    }

    @And(
            "clicks continue on the signed into your GOV.UK One Login page and login to driving licence Cri")
    public void clicksContinueOnTheSignedIntoYourGOVUKOneLoginPageAndLoginToDrivingLicenceCri() {
        proveYourIdentityGovUkPage.waitForPageToLoad();
        proveYourIdentityGovUkPage.ContinueToEnterDrivngLicence();
        try {
            if (deviceSelectionPage.isDeviceSelectionScreenPresent()) {
                deviceSelectionPage.selectNoMobileDeviceAndContinue();
                deviceSelectionPage.selectNoIphoneOrAndroidAndContinue();
            }
        } catch (NullPointerException e) {
            LOGGER.warning(
                    "No environment variable specified, please specify a variable for runs in Integration");
        }
        driverLicenceDocCheckPage.waitForPageToLoad();
        driverLicenceDocCheckPage.drivingLicenceDocCheck();
    }

    @Given("User on Orchestrator Stub and click on full journey route for App User")
    public void userOnOrchestratorStubAndClickOnFullJourneyRouteForAppUser() {
        Driver.get().get(configurationService.getOrchestratorStubUrl());
        BrowserUtils.waitForPageToLoad(10);
        proveYourIdentityGovUkPage.selectAppUserId();
        proveYourIdentityGovUkPage.fullJourneyRoute();
    }

    @And("clicks continue on the signed into your GOV.UK One Login page for App Journey")
    public void clicksContinueOnTheSignedIntoYourGOVUKOneLoginPageForAppJourney() {
        proveYourIdentityGovUkPage.SignToAppJourney();
    }

    @Given("User on Orchestrator and click on full journey route")
    public void userOnOrchestratorAndClickOnFullJourneyRoute() {
        Driver.get().get(configurationService.getOrchestratorStubUrl());
        BrowserUtils.waitForPageToLoad(10);
        proveYourIdentityGovUkPage.selectAppUserId();
        proveYourIdentityGovUkPage.fullJourneyRoute();
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
}
