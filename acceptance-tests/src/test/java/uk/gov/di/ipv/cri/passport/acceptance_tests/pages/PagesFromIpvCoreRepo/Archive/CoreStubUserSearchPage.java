package uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo.Archive;

import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;
import org.openqa.selenium.support.PageFactory;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.Driver;

public class CoreStubUserSearchPage {
    public CoreStubUserSearchPage() {
        PageFactory.initElements(Driver.get(), this);
    }

    @FindBy(id = "rowNumber")
    public WebElement rowNumberBox;

    @FindBy(xpath = "//form[@action='/authorize']/div/button")
    public WebElement goToBuildPassportButton;
}
