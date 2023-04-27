package uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo;

import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;
import org.openqa.selenium.support.PageFactory;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.Driver;

public class CheckingYourDetailsPage extends GlobalPage {
    public CheckingYourDetailsPage() {
        PageFactory.initElements(Driver.get(), this);
    }

    private static final By CONTINUE_BUTTON = By.cssSelector("#continue");
    private static final By SELECT_USER = By.xpath("//*[@id='test_data']");
    private static final String USER_DATA_DIRECTORY = "src/test/resources/data/";
    private static final By SUBMIT_AUTH = By.xpath("//*[@name='submit']");
    private static final By FRAUD_SCORE = By.cssSelector("#fraud");

    public void clickContinue() {
        clickElement(CONTINUE_BUTTON);
    }

    @FindBy(xpath = "//button[@class='govuk-button button']")
    public WebElement Continue;
}
