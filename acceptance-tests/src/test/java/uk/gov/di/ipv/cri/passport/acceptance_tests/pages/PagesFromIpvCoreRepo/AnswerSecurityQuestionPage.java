package uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo;

import org.openqa.selenium.By;

public class AnswerSecurityQuestionPage extends GlobalPage {

    private static final By CONTINUE = By.cssSelector("#submitButton");

    public void clickContinue() {
        clickElement(CONTINUE);
    }
}
