package uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo;

import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;
import org.openqa.selenium.support.PageFactory;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.Driver;

public class PassportPage {
    @FindBy(xpath = "//*[@id='test_data']")
    public WebElement SelectCRIData;

    @FindBy(xpath = "//*[@class='govuk-button']")
    public WebElement submitdatagenerateauth;

    public PassportPage() {
        PageFactory.initElements(Driver.get(), this);
    }

    @FindBy(id = "passportNumber")
    public WebElement PassportNumber;

    @FindBy(id = "surname")
    public WebElement Surname;

    @FindBy(xpath = "//*[@id=\"firstName\"]")
    public WebElement FirstName;

    @FindBy(id = "dateOfBirth-day")
    public WebElement birthDay;

    @FindBy(id = "dateOfBirth-month")
    public WebElement birthMonth;

    @FindBy(id = "dateOfBirth-year")
    public WebElement birthYear;

    @FindBy(id = "expiryDate-day")
    public WebElement PassportExpiryDay;

    @FindBy(id = "expiryDate-month")
    public WebElement PassportExpiryMonth;

    @FindBy(id = "expiryDate-year")
    public WebElement PassportExpiryYear;

    @FindBy(xpath = "//button[@class='govuk-button button']")
    public WebElement Continue;

    @FindBy(xpath = "//h1[@id='header']")
    public WebElement PassportPageHeader;
}
