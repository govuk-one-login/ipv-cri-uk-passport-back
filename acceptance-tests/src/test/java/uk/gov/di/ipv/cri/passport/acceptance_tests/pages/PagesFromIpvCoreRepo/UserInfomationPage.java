package uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo;

import org.junit.Assert;
import org.openqa.selenium.By;

public class UserInfomationPage extends GlobalPage {

    private static final By PAGE_HEADER = By.cssSelector(".govuk-heading-l");

    public void validateUserInformationTitle() {
        Assert.assertTrue(
                "Page Header not returned as expected",
                (getText(PAGE_HEADER).contains("User information")));
    }
}
