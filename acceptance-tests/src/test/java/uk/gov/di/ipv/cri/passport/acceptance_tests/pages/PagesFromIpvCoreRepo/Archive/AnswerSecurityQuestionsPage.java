package uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo.Archive;

import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;
import org.openqa.selenium.support.PageFactory;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.Driver;

public class AnswerSecurityQuestionsPage {
    public AnswerSecurityQuestionsPage() {
        PageFactory.initElements(Driver.get(), this);
    }

    @FindBy(xpath = "//a[@role='button']")
    public WebElement Start;

    @FindBy(xpath = "//button[@class='govuk-button button']")
    public WebElement Continue;
}
