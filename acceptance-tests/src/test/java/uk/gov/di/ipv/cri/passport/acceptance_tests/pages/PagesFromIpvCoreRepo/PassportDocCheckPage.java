package uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo;

import org.openqa.selenium.By;

public class PassportDocCheckPage extends GlobalPage {

    private static final By CONTINUE_CHECKBOX = By.cssSelector("#journey");
    private static final By CONTINUE_GOV_UK = By.cssSelector("#submitButton");
    private static final By QUESTION_LABEL = By.cssSelector(".govuk-label.govuk-radios__label");

    public void waitForPageToLoad() {
        waitForElementVisible(QUESTION_LABEL, 30);
    }

    public void passportDocCheck() {
        clickElement(CONTINUE_CHECKBOX);
        clickElement(CONTINUE_GOV_UK);
    }
}
