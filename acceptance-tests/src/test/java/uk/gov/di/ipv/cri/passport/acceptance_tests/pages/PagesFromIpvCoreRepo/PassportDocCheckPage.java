package uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo;

import org.junit.Assert;
import org.openqa.selenium.By;
import org.openqa.selenium.support.ui.Select;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.UtilitiesFromIpvRepo.BrowserUtils;

public class PassportDocCheckPage extends GlobalPage {

    private static final By CONTINUE_CHECKBOX = By.cssSelector("#journey");
    private static final By CONTINUE_GOV_UK = By.cssSelector("#submitButton");
    private static final By QUESTION_LABEL = By.cssSelector(".govuk-label.govuk-radios__label");
    private static final By AUTHORIZATION = By.cssSelector("#endpoint");
    private static final By OAUTH_ERROR = By.cssSelector("#requested_oauth_error");
    private static final By OAUTH_ERROR_TAB = By.cssSelector("#tab_oauthError");
    private static final By SUBMIT_AUTH = By.xpath("//*[@name='submit']");

    public void waitForPageToLoad() {
        waitForElementVisible(QUESTION_LABEL, 30);
    }

    public void passportDocCheck() {
        clickElement(CONTINUE_CHECKBOX);
        clickElement(CONTINUE_GOV_UK);
    }

    public void checkinAppStub() {
        Assert.assertEquals(
                "DOC Checking App (Stub)", new IpvCoreFrontPageArchive().appStubHdr.getText());
    }

    public void generateOAuthError() {
        clickElement(OAUTH_ERROR_TAB);
        clickElement(AUTHORIZATION);
        Select selecte = new Select(getCurrentDriver().findElement(OAUTH_ERROR));
        selecte.selectByValue("access_denied");
        clickElement(SUBMIT_AUTH);
        BrowserUtils.waitForPageToLoad(10);
    }
}
