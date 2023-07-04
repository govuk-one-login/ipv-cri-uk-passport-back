package uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo;

import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;
import org.openqa.selenium.support.PageFactory;
import org.openqa.selenium.support.ui.Select;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.Driver;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.UtilitiesFromIpvRepo.BrowserUtils;

import static uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.UtilitiesFromIpvRepo.PageObjectSupport.clickElement;

public class FraudCheckStubPage {
    private static final By SUBMIT_AUTH = By.xpath("//input[@name='submit']");
    private static final By JWT_CHECK_BOX = By.cssSelector("#vcExpiryFlg");

    public FraudCheckStubPage() {
        PageFactory.initElements(Driver.get(), this);
    }

    @FindBy(id = "jsonPayload")
    public WebElement JSONPayLoader;

    @FindBy(id = "fraud")
    public WebElement FraudValue;

    @FindBy(xpath = "//input[@name='submit']")
    public WebElement SubmitDataAndGenerateAuthCode;

    public static void enterFraudDetails() {
        Select select = new Select(new IpvCoreFrontPageArchive().SelectfraudCRIData);
        select.selectByValue("Kenneth Decerqueira (Valid Experian) Fraud");
        new IpvCoreFrontPageArchive().fraudscore.sendKeys("2");
        new PassportPage().SelectCRIData.click();
        BrowserUtils.waitForPageToLoad(10);
        clickElement(JWT_CHECK_BOX);
        new IpvCoreFrontPageArchive().JWT_EXP_HR.clear();
        new IpvCoreFrontPageArchive().JWT_EXP_HR.sendKeys("4");
        new PassportPage().submitdatagenerateauth.click();
    }

    public static void clickContinue() {
        clickElement(SUBMIT_AUTH);
    }

    public static void enterFraudDetailsWithoutJwtExp() {
        Select select = new Select(new IpvCoreFrontPageArchive().SelectfraudCRIData);
        select.selectByValue("Kenneth Decerqueira (Valid Experian) Fraud");
        new IpvCoreFrontPageArchive().fraudscore.sendKeys("2");
        new PassportPage().SelectCRIData.click();
        BrowserUtils.waitForPageToLoad(10);
        new PassportPage().submitdatagenerateauth.click();
    }
}
