package uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo;

import com.amazonaws.services.sns.AmazonSNS;
import com.amazonaws.services.sns.model.PublishRequest;
import com.amazonaws.services.sns.model.PublishResult;
import org.junit.Assert;
import org.openqa.selenium.By;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.UtilitiesFromIpvRepo.BrowserUtils;
import utilsFromIpvRepo.UiSupport;

import java.security.NoSuchAlgorithmException;

public class ProveYourIdentityGovUkPage extends GlobalPage {

    private static final By PROVE_ANOTHER_WAY = By.cssSelector("#journey-2");
    private static final By FULL_JOURNEY_ROUTE = By.xpath("//*[@value='Full journey route']");
    private static final By DEBUG_ROUTE = By.xpath("//*[@value='Debug route']");
    private static final By UK_PASSPORT_CRI = By.cssSelector("#cri-link-ukPassport");
    private static final By UK_DCMAW_STUB = By.cssSelector("#cri-link-stubDcmaw");
    private static final By USER_INFO = By.cssSelector(".govuk-heading-l");
    private static final By CONTINUE_BUTTON = By.cssSelector("#submitButton");
    private static final By USER_ID_FIELD = By.cssSelector("#userIdText");
    private static final By SIGN_OUT = By.xpath("//*[@class='one-login-header__nav__link']");
    private static final By SIGN_OUT_HDR =
            By.xpath("//h1[@class='govuk-heading-l govuk-!-margin-top-0 govuk-!-margin-bottom-3']");
    private static final By ERROR_JOURNEY_BUTTON = By.xpath("//*[@value='Error journey route']");

    public static String userId;
    public static String userId2 = "test703456";
    private static final By MOBILE_APP_USER_ID_OPTION =
            By.xpath("//*[@id=\"userIdSelect\"]/option[2]");

    public void waitForPageToLoad() {
        waitForElementVisible(USER_INFO, 30);
    }

    public void fullJourneyRoute() {
        clickElement(FULL_JOURNEY_ROUTE);
    }

    public void ContinueToEnterPassport() {
        clickElement(CONTINUE_BUTTON);
    }

    public static void pubTopic(AmazonSNS snsClient, String message, String topicArn) {
        PublishRequest request = new PublishRequest().withMessage(message).withTopicArn(topicArn);

        PublishResult result = snsClient.publish(request);
        System.out.println(
                result.getMessageId()
                        + " Message sent. Status is "
                        + result.getSdkHttpMetadata().getHttpStatusCode());
    }

    public void proveanotherway() {
        clickElement(PROVE_ANOTHER_WAY);
        clickElement(CONTINUE_BUTTON);
    }

    public void userInfo() {
        BrowserUtils.waitForPageToLoad(10);
        Assert.assertEquals("User information", getText(USER_INFO));
    }

    public void debugRoute() {
        clickElement(DEBUG_ROUTE);
        clickElement(UK_PASSPORT_CRI);
    }

    public void debugRouteMobile() {
        clickElement(DEBUG_ROUTE);
        clickElement(UK_DCMAW_STUB);
    }

    public void fullJourneyRouteBuild() {
        clickElement(FULL_JOURNEY_ROUTE);
        clickElement(CONTINUE_BUTTON);
    }

    public void generateRandomUserId() throws NoSuchAlgorithmException {
        userId = "Test-" + UiSupport.generateRandomAlphanumeric(15);
    }

    public void inputuserId() {
        populateField(USER_ID_FIELD, userId);
    }

    public void selectAppUserId() {
        clickElement(MOBILE_APP_USER_ID_OPTION);
    }

    public void SignToAppJourney() {
        clickElement(CONTINUE_BUTTON);
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
