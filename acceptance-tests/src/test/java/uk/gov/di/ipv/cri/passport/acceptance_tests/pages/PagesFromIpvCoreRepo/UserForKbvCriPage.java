package uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo;

import org.junit.Assert;
import org.openqa.selenium.By;
import org.openqa.selenium.support.ui.Select;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.Driver;

public class UserForKbvCriPage extends GlobalPage {

    private static final By PAGE_HEADING = By.cssSelector(".govuk-heading-xl");
    private static final By SEARCH_BOX = By.cssSelector(".govuk-input.govuk-input--width-20");
    private static final By SEARCH_BUTTON = By.xpath("//button[text()='Search']");
    private static final By CONTINUE_BUTTON = By.xpath("//button[@name='submitButton']");
    private static final By SELECT_USER = By.xpath("//*[@id='test_data']");
    private static final By KBV_VER = By.cssSelector("#verification");
    private static final By SUBMIT_AUTH = By.xpath("//*[@name='submit']");

    private String PAGE_TITLE_PREFIX = "user for kbv cri ";

    public void isUserOnKbvCriPage() {
        String environment = System.getProperty("env").toLowerCase();
        String pageTitle = getCurrentDriver().findElement(PAGE_HEADING).getText().toLowerCase();
        Assert.assertEquals(
                "The user is not on the correct page for the environment specified: " + environment,
                PAGE_TITLE_PREFIX + environment,
                pageTitle);
    }

    public void enterUsernameAndSearch(String username) {
        populateDetailsInFields(SEARCH_BOX, username);
        clickElement(SEARCH_BUTTON);
    }

    public void updateKBVCriStub() {
        String kbvVer = "2";
        clickElement(CONTINUE_BUTTON);
        Select select = new Select(getCurrentDriver().findElement(SELECT_USER));
        select.selectByValue("Kenneth Decerqueira (Valid Experian) KBV");
        clickElement(SELECT_USER);
        populateField(KBV_VER, kbvVer);
        clickElement(SUBMIT_AUTH);
    }

    public void clickBrowserButton() {
        Driver.get().navigate().back();
    }
}
