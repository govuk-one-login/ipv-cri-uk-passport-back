package uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo;

import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;

public class YouHaveSuccessfullyProvedYourIdentityPage {

    @FindBy(xpath = "//a[@role='button']")
    public WebElement Continue;
}
