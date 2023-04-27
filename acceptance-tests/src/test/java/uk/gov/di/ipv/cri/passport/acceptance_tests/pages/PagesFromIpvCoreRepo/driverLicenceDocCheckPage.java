package uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo;

import org.openqa.selenium.By;

public class driverLicenceDocCheckPage extends GlobalPage {

    private static final By CONTINUE_CHECKBOX = By.cssSelector("#journey-2");
    private static final By CONTINUE_GOV_UK = By.cssSelector("#submitButton");
    private static final By QUESTION_LABEL = By.cssSelector(".govuk-label.govuk-radios__label");

    public void waitForPageToLoad() {
        waitForElementVisible(QUESTION_LABEL, 30);
    }

    public void drivingLicenceDocCheck() {
        clickElement(CONTINUE_CHECKBOX);
        clickElement(CONTINUE_GOV_UK);
    }
}
