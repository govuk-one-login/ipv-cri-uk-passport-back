package uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo;

import org.junit.Assert;
import org.openqa.selenium.By;
import utilsFromIpvRepo.UiSupport;

import java.security.NoSuchAlgorithmException;

public class ProveYourIdentityGovUkPage extends GlobalPage {

    private static final By PROVE_ANOTHER_WAY = By.cssSelector("#journey-2");
    private static final By FULL_JOURNEY_ROUTE = By.xpath("//*[@value='Full journey route']");
    private static final By DEBUG_ROUTE = By.xpath("//*[@value='Debug route']");
    private static final By UK_PASSPORT_CRI = By.cssSelector("#cri-link-ukPassport");
    private static final By USER_INFO = By.cssSelector(".govuk-heading-l");
    private static final By CONTINUE_BUTTON = By.cssSelector("#submitButton");
    private static final By JOURNEY_RADIO_BUTTON = By.cssSelector("#journey");
    private static final By USER_ID_FIELD = By.cssSelector("#userIdText");
    private static final By SIGN_OUT = By.xpath("//*[@class='one-login-header__nav__link']");
    private static final By SIGN_OUT_HDR =
            By.xpath("//h1[@class='govuk-heading-l govuk-!-margin-top-0 govuk-!-margin-bottom-3']");
    private static final By ERROR_JOURNEY_BUTTON = By.xpath("//*[@value='Error journey route']");

    public static String userId;

    public void waitForPageToLoad() {
        waitForElementVisible(USER_INFO, 30);
    }

    public void fullJourneyRoute() {
        clickElement(FULL_JOURNEY_ROUTE);
    }

    public void ContinueToEnterPassport() {
        clickElement(JOURNEY_RADIO_BUTTON);
        clickElement(CONTINUE_BUTTON);
    }

    public void generateRandomUserId() throws NoSuchAlgorithmException {
        userId = "Test-" + UiSupport.generateRandomAlphanumeric(15);
    }

    public void inputuserId() {
        populateField(USER_ID_FIELD, userId);
    }

    public void clickSignOut() {
        clickElement(SIGN_OUT);
    }

    public void signOutPage() {
        Assert.assertEquals("You have signed out", getText(SIGN_OUT_HDR));
    }

    public void errorJourneyRoute() {
        clickElement(ERROR_JOURNEY_BUTTON);
    }
}
