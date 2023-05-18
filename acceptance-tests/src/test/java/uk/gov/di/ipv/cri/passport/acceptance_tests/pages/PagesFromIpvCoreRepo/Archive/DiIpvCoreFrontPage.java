package uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo.Archive;

import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;
import org.openqa.selenium.support.PageFactory;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.Driver;

public class DiIpvCoreFrontPage {

    @FindBy(xpath = "//*[@class='govuk-details__text']//pre")
    public WebElement Verifiablejson;

    public DiIpvCoreFrontPage() {
        PageFactory.initElements(Driver.get(), this);
    }

    @FindBy(xpath = "//input[@value='Authorize and Return']")
    public WebElement AuthorizeAndReturn;

    @FindBy(xpath = "//*[@class='govuk-summary-list__value']//pre")
    public WebElement VerifiableCredentialJSONPayload;
}
