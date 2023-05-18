package uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo.Archive;

import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;
import org.openqa.selenium.support.PageFactory;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.Driver;

public class KnowledgeBasedVerificationStubPage {
    public KnowledgeBasedVerificationStubPage() {
        PageFactory.initElements(Driver.get(), this);
    }

    @FindBy(id = "jsonPayload")
    public WebElement JSONPayLoader;

    @FindBy(id = "verification")
    public WebElement Verification;

    @FindBy(xpath = "//input[@name='submit']")
    public WebElement SubmitDataAndGenerateAuthCode;
}
