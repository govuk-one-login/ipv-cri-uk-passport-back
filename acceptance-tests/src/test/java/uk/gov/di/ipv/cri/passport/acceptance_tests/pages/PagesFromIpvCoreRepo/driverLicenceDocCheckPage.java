package uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo;

import org.openqa.selenium.By;

public class driverLicenceDocCheckPage extends GlobalPage {
    private static final By QUESTION_LABEL = By.cssSelector(".govuk-label.govuk-radios__label");

    public void waitForPageToLoad() {
        waitForElementVisible(QUESTION_LABEL, 30);
    }
}
