package uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo.Archive;

import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;
import org.openqa.selenium.support.PageFactory;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.Driver;

public class CoreStubCrisPage {
    public CoreStubCrisPage() {
        PageFactory.initElements(Driver.get(), this);
    }

    @FindBy(xpath = "//*[@id=\"main-content\"]/p/a/button")
    public WebElement VisitCredentialIssuersLink;

    @FindBy(xpath = "//input[@value='Build Passport']")
    public WebElement BuildPassportLink;
}
