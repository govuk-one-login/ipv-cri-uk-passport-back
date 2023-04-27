package uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo;

import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;
import org.openqa.selenium.support.PageFactory;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.Driver;

public class PassportPage {

    @FindBy(
            xpath =
                    "//*[@class='govuk-error-summary error-summary']//*[@class='govuk-error-summary__body']//*[@class='govuk-list govuk-error-summary__list']//*[contains(@href,'#passportNumber')]")
    public WebElement InvalidPassportNumberError;

    @FindBy(
            xpath =
                    "//*[@class='govuk-error-summary error-summary']//*[@class='govuk-error-summary__body']//*[@class='govuk-list govuk-error-summary__list']//*[contains(@href,'#firstName')]")
    public WebElement InvalidPassportFirstName;

    @FindBy(
            xpath =
                    "//*[@class='govuk-error-summary error-summary']//*[@class='govuk-error-summary__body']//*[@class='govuk-list govuk-error-summary__list']//*[contains(@href,'#surname')]")
    public WebElement InvalidPassportSurname;

    @FindBy(
            xpath =
                    "//*[@class='govuk-error-summary error-summary']//*[@class='govuk-error-summary__body']//*[@class='govuk-list govuk-error-summary__list']")
    public WebElement InvalidDOB;

    @FindBy(
            xpath =
                    "//*[@class='govuk-error-summary error-summary']//*[@class='govuk-error-summary__body']//*[@class='govuk-list govuk-error-summary__list']//*[contains(@href,'#expiryDate-day')]")
    public WebElement InvalidExpiryDate;

    @FindBy(xpath = "//*[@class='govuk-notification-banner__content']//h2")
    public WebElement Passportnotfound;

    @FindBy(xpath = "//*[@class='govuk-heading-l']")
    public WebElement Passportnotfoundonretry;

    @FindBy(xpath = "//*[@class='govuk-inset-text']//*[contains(@href,'prove-another-way')]")
    public WebElement proveanotherway;

    @FindBy(xpath = "//*[@class='govuk-radios__item']//*[@id='proveAnotherWayRadio']")
    public WebElement proveidentityanotherway;

    @FindBy(xpath = "//*[@class='govuk-heading-l']")
    public WebElement sorrythereisproblem;

    @FindBy(xpath = "//*[@class='govuk-radios__item']//*[@id='proveAnotherWayRadio-retry']")
    public WebElement enterpassportdetails;

    @FindBy(xpath = "//*[@id=\"main-content\"]/div[1]/h1")
    public WebElement PassportStub;

    @FindBy(xpath = "//*[@id='test_data']")
    public WebElement SelectCRIData;

    @FindBy(xpath = "//*[@id='strength']")
    public WebElement Strenght;

    @FindBy(xpath = "//*[@id='validity']")
    public WebElement Validity;

    @FindBy(xpath = "//*[@name='requested_oauth_error_endpoint']")
    public WebElement Authorization;

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

    @FindBy(id = "middleNames")
    public WebElement MiddleNames;

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

    @FindBy(id = "passportNumber-label")
    public WebElement passportNumberlbl;

    @FindBy(id = "surname-label")
    public WebElement surNamelbl;

    @FindBy(id = "firstName-label")
    public WebElement firstNamelbl;

    @FindBy(id = "middleNames-label")
    public WebElement middleNamelbl;

    @FindBy(xpath = "//legend[normalize-space()='Dyddiad geni']")
    public WebElement doblbl;

    @FindBy(id = "dateOfBirth-hint")
    public WebElement dobhint;

    @FindBy(xpath = "//*[@for='dateOfBirth-day']")
    public WebElement dobDay;

    @FindBy(xpath = "//*[@for='dateOfBirth-month']")
    public WebElement dobMonth;

    @FindBy(xpath = "//*[@for='dateOfBirth-year']")
    public WebElement dobYear;

    @FindBy(xpath = "//legend[normalize-space()='Dyddiad dod i ben']")
    public WebElement expiryDatelbl;

    @FindBy(id = "expiryDate-hint")
    public WebElement expiryDatehint;

    @FindBy(xpath = "//*[@for='expiryDate-day']")
    public WebElement expiryDateDay;

    @FindBy(xpath = "//*[@for='expiryDate-month']")
    public WebElement expiryDateMonth;

    @FindBy(xpath = "//*[@for='expiryDate-year']")
    public WebElement expiryDateYear;
}
