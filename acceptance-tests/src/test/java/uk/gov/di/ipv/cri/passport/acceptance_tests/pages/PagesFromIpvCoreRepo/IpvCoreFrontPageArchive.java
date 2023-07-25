package uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo;

import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;
import org.openqa.selenium.support.PageFactory;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.Driver;

public class IpvCoreFrontPageArchive {

    @FindBy(xpath = "//*[@class='govuk-heading-xl']")
    public WebElement appStubHdr;

    public IpvCoreFrontPageArchive() {
        PageFactory.initElements(Driver.get(), this);
    }

    @FindBy(xpath = "//*[@id=\"main-content\"]/div[1]/h1")
    public WebElement FraudStub;

    @FindBy(id = "test_data")
    public WebElement SelectfraudCRIData;

    @FindBy(xpath = "//*[@name=\"identityFraudScore\"]")
    public WebElement fraudscore;

    @FindBy(id = "test_data")
    public WebElement SelectkbvCRIData;

    @FindBy(xpath = "//*[@name=\"verificationScore\"]")
    public WebElement kbvscore;

    @FindBy(xpath = "//*[@id='header']")
    public WebElement journeycomplete;

    @FindBy(xpath = "//*[@id='header']")
    public WebElement Kbvheader;

    @FindBy(xpath = "//*[@id='expHours']")
    public WebElement JWT_EXP_HR;

    @FindBy(xpath = "//*[normalize-space()='Raw User Info Object']")
    public WebElement RAW_JSON;

    @FindBy(xpath = "//textarea[@id='ci']")
    public WebElement updateci;
}
