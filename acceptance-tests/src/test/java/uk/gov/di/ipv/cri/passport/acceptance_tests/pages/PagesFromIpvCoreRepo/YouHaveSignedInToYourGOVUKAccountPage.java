package uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo;

import com.fasterxml.jackson.core.JsonParser;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;
import org.openqa.selenium.support.PageFactory;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.Driver;

public class YouHaveSignedInToYourGOVUKAccountPage {

    public JsonParser Pagecontent;

    public YouHaveSignedInToYourGOVUKAccountPage() {
        PageFactory.initElements(Driver.get(), this);
    }

    @FindBy(id = "submitButton")
    public WebElement Continue;

    @FindBy(xpath = "//*[@class='govuk-cookie-banner__heading govuk-heading-m']")
    public WebElement GOVUKbanner;
}
