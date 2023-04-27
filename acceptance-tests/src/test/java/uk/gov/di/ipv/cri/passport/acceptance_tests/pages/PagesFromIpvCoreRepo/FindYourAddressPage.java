package uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo;

import org.json.JSONObject;
import org.junit.Assert;
import org.openqa.selenium.By;

import java.io.IOException;

public class FindYourAddressPage extends GlobalPage {

    private static final By ADDRESS_HDR = By.cssSelector("#header");
    private static final By POSTCODE_FIELD = By.cssSelector("#addressSearch");
    private static final By FIND_ADDRESS_BUTTON = By.cssSelector("#continue");

    private static final String USER_DATA_DIRECTORY = "src/test/resources/data/";

    public void waitForPageToLoad() {
        waitForElementVisible(ADDRESS_HDR, 30);
    }

    public static void validateAddPage() {
        Assert.assertEquals("Find your address", getText(ADDRESS_HDR));
    }

    public void searchForUserAddress(String userName) throws IOException {
        JSONObject userDetailsObject =
                new JSONObject(
                        generateStringFromJsonPayloadResource(USER_DATA_DIRECTORY, userName));
        populateField(POSTCODE_FIELD, userDetailsObject.getString("postcode"));
        clickElement(FIND_ADDRESS_BUTTON);
    }
}
