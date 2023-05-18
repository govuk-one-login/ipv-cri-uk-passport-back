package uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo;

import org.openqa.selenium.By;

public class ExperianUserSearchResultsPage extends GlobalPage {

    private static final By GO_TO_KBV_CRI = By.xpath("//a[contains(@href,'/authorize')]");

    public void goToKbvCri() {
        clickElement(GO_TO_KBV_CRI);
    }
}
