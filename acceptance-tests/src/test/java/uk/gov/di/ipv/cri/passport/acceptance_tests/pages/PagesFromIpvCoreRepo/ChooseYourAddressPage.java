package uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo;

import org.json.JSONObject;
import org.junit.Assert;
import org.openqa.selenium.By;
import org.openqa.selenium.support.ui.Select;

import java.io.IOException;

public class ChooseYourAddressPage extends GlobalPage {

    private static final By ADDRESS_DROPDOWN = By.cssSelector("#addressResults");
    private static final By CHOOSE_ADDRESS_BUTTON = By.cssSelector("#continue");
    private static final By SELECT_USER = By.xpath("//*[@id='test_data']");
    private static final String USER_DATA_DIRECTORY = "src/test/resources/Data/";
    private static final By SUBMIT_AUTH = By.xpath("//*[@name='submit']");
    private static final By JWT_CHECK_BOX = By.cssSelector("#vcExpiryFlg");
    private static final By ERROR_HDR = By.cssSelector("#header");

    public void selectUserAddress(String userName, String addressCriSuccess) throws IOException {
        JSONObject userDetailsObject =
                new JSONObject(
                        generateStringFromJsonPayloadResource(USER_DATA_DIRECTORY, userName));
        String addressDropDownValue;
        if (addressCriSuccess.equals("Successfully")) {
            addressDropDownValue = userDetailsObject.getString("address");
        } else {
            addressDropDownValue = userDetailsObject.getString("incorrectAddress");
        }
        Select select = new Select(getCurrentDriver().findElement(ADDRESS_DROPDOWN));
        select.selectByValue(addressDropDownValue);
        clickElement(CHOOSE_ADDRESS_BUTTON);
    }

    public void selectStubUserAddress() {
        Select select = new Select(getCurrentDriver().findElement(SELECT_USER));
        select.selectByValue("Kenneth Decerqueira (Valid Experian) Address");
        clickElement(SELECT_USER);
        clickElement(JWT_CHECK_BOX);
        new IpvCoreFrontPageArchive().JWT_EXP_HR.clear();
        new IpvCoreFrontPageArchive().JWT_EXP_HR.sendKeys("4");
        clickElement(SUBMIT_AUTH);
    }

    public void backButtonErrPage() {
        Assert.assertEquals("Sorry, you cannot go back", getText(ERROR_HDR));
    }
}
