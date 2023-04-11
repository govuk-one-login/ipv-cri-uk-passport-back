package uk.gov.di.ipv.cri.passport.acceptance_tests.pages;

import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;
import org.openqa.selenium.support.PageFactory;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.Driver;

public class OrchestratorStubPage {

    public OrchestratorStubPage() {
        PageFactory.initElements(Driver.get(), this);
    }

    @FindBy(xpath = "//input[@value='Debug route']")
    public WebElement DebugRoute;

    @FindBy(xpath = "//*[@id='cri-link-ukPassport']")
    public WebElement UkPassport;
}
