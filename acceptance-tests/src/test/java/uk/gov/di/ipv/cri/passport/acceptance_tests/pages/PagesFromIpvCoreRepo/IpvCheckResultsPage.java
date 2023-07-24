package uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo;

import org.junit.Assert;
import org.openqa.selenium.By;

public class IpvCheckResultsPage extends GlobalPage {

    private static final By CONTINUE = By.cssSelector("#submitButton");
    private static final By SUCCESS_HDR = By.cssSelector("#header");
    private static final By REUSE_TXT =
            By.xpath("//*[contains(text(),'If you have not signed in to GOV.UK One Login in a')]");

    public void validateIpvCheckResults(String identityValidity) {
        Assert.assertEquals("Continue to the service you want to use", getText(SUCCESS_HDR));
    }

    public void clickContinue() {
        clickElement(CONTINUE);
    }

    public void validateRebranding() {
        Assert.assertEquals(
                "If you have not signed in to GOV.UK One Login in a while, you might want to check your details are still correct.",
                getText(REUSE_TXT));
    }
}
