package uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo;

import org.json.JSONObject;
import org.openqa.selenium.By;

import java.io.IOException;

public class CheckAndConfirmYourAddressPage extends GlobalPage {

    private static final By WHEN_DID_YOU_START_LIVING_HERE = By.cssSelector("#addressYearFrom");
    // private static final By CONTINUE_BUTTON = By.cssSelector("#continue");
    private static final By CONFIRM_ADDRESS_DETATILS = By.xpath("//button[@data-id='next']");
    private static final String USER_DATA_DIRECTORY = "src/test/resources/Data/";

    public void checkAndConfirmUserAddress(String userName) throws IOException {
        JSONObject userDetailsObject =
                new JSONObject(
                        generateStringFromJsonPayloadResource(USER_DATA_DIRECTORY, userName));
        populateField(WHEN_DID_YOU_START_LIVING_HERE, userDetailsObject.getString("yearMovedIn"));
        clickElement(CONTINUE_BUTTON);
        clickElement(CONFIRM_ADDRESS_DETATILS);
    }
}
