package uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo.Archive;

import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;
import org.openqa.selenium.support.PageFactory;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo.GlobalPage;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.Driver;

public class CheckYourDetails {
    public CheckYourDetails() {
        PageFactory.initElements(Driver.get(), this);
    }

    @FindBy(xpath = "//button[@class='govuk-button button']")
    public WebElement Continue;

    public static class AnswerSecurityQuestionPage extends GlobalPage {

        private static final By CONTINUE = By.cssSelector("#submitButton");

        public void clickContinue() {
            clickElement(CONTINUE);
        }
    }
}
