package uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo;

import org.junit.Assert;
import org.openqa.selenium.By;

public class UserInfomationPage extends GlobalPage {

    private static final By USER_INFO_CORE_IDENTITY_CLAIM =
            By.cssSelector("#user-info-core-identity-claim");
    private static final By USER_INFO_ADDRESS_CLAIM = By.cssSelector("#user-info-address-claim");
    private static final By USER_INFO_PASSPORT_CLAIM = By.cssSelector("#user-info-passport-claim");
    private static final By PAGE_HEADER = By.cssSelector(".govuk-heading-l");
    public static final String CLAIM_EXPECTED_VALUE = "true";

    public void validateCoreIdentityClaim() {
        Assert.assertEquals(
                "The Core Identity Claim value returned was incorrectly. Expected: "
                        + CLAIM_EXPECTED_VALUE
                        + " Actual: "
                        + getText(USER_INFO_CORE_IDENTITY_CLAIM),
                CLAIM_EXPECTED_VALUE,
                getText(USER_INFO_CORE_IDENTITY_CLAIM));
    }

    public void validateAddressClaim() {
        Assert.assertEquals(
                "The Address Claim value returned was incorrectly. Expected: "
                        + CLAIM_EXPECTED_VALUE
                        + " Actual: "
                        + getText(USER_INFO_ADDRESS_CLAIM),
                CLAIM_EXPECTED_VALUE,
                getText(USER_INFO_ADDRESS_CLAIM));
    }

    public void validatePassportClaim() {
        Assert.assertEquals(
                "The Passport Claim value returned was incorrectly. Expected: "
                        + CLAIM_EXPECTED_VALUE
                        + " Actual: "
                        + getText(USER_INFO_PASSPORT_CLAIM),
                CLAIM_EXPECTED_VALUE,
                getText(USER_INFO_ADDRESS_CLAIM));
    }

    public void validateUserInformationTitle() {
        Assert.assertTrue(
                "Page Header not returned as expected",
                (getText(PAGE_HEADER).contains("User information")));
    }
}
