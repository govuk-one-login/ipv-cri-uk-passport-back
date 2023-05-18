package uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo;

import org.openqa.selenium.By;

public class IpvCoreStubHomepage extends GlobalPage {

    private static final By VISIT_CREDENTIAL_ISSUERS = By.cssSelector(".govuk-button");

    public void clickVisitCredentialIssuers() {
        clickElement(VISIT_CREDENTIAL_ISSUERS);
    }
}
