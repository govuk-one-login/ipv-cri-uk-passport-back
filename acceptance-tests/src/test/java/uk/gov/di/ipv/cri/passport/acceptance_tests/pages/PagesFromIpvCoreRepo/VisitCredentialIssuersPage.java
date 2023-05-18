package uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo;

import org.openqa.selenium.By;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class VisitCredentialIssuersPage extends GlobalPage {

    private static final By KBV_CRI_BUILD = By.xpath("//input[@value='KBV CRI Build']");
    private static final By KBV_CRI_STAGING = By.xpath("//input[@value='KBV CRI Staging']");
    private static final By KBV_CRI_INT = By.xpath("//input[@value='KBV CRI Integration']");

    private static final Logger LOGGER = LoggerFactory.getLogger(VisitCredentialIssuersPage.class);

    public void visitKbvCredentialIssuer() {
        String environment = System.getProperty("env");
        if (environment.equals("build")) {
            clickElement(KBV_CRI_BUILD);
        } else if (environment.equals("staging")) {
            clickElement(KBV_CRI_STAGING);
        } else if (environment.equals("integation")) {
            clickElement(KBV_CRI_INT);
        } else {
            LOGGER.warn(
                    "A valid Environment Value was not specified in the run configuration - Using default env variable 'staging'");
            clickElement(KBV_CRI_STAGING);
        }
    }
}
