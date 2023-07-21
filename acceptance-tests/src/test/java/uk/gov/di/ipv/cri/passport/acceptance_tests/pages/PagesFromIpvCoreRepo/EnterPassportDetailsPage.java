package uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.json.JSONObject;
import org.junit.Assert;
import org.openqa.selenium.By;
import org.openqa.selenium.Cookie;
import org.openqa.selenium.support.PageFactory;
import org.openqa.selenium.support.ui.Select;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.Driver;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.UtilitiesFromIpvRepo.*;

import java.io.IOException;
import java.util.logging.Logger;

public class EnterPassportDetailsPage extends GlobalPage {

    private static final By PASSPORT_NUMBER_FIELD = By.cssSelector("#passportNumber");
    private static final By SURNAME_FIELD = By.cssSelector("#surname");
    private static final By FIRST_NAME_FIELD = By.cssSelector("#firstName");
    private static final By DATE_OF_BIRTH_DAY_FIELD = By.cssSelector("#dateOfBirth-day");
    private static final By DATE_OF_BIRTH_MONTH_FIELD = By.cssSelector("#dateOfBirth-month");
    private static final By DATE_OF_BIRTH_YEAR_FIELD = By.cssSelector("#dateOfBirth-year");
    private static final By EXPIRY_DATE_DAY_FIELD = By.cssSelector("#expiryDate-day");
    private static final By EXPIRY_DATE_MONTH_FIELD = By.cssSelector("#expiryDate-month");
    private static final By EXPIRY_DATE_YEAR_FIELD = By.cssSelector("#expiryDate-year");
    private static final By CONTINUE_BUTTON = By.xpath("//button[@name='submitButton']");
    private static final By INVALID_PASSPORT_ERR = By.cssSelector("a[href='#passportNumber']");
    private static final By INVALID_SURNAME_ERR = By.cssSelector("a[href='#surname']");
    private static final By INVALID_FIRSTNAME_ERR = By.cssSelector("a[href='#firstName']");
    private static final By INVALID_DOB_ERR = By.cssSelector("a[href='#dateOfBirth-month']");
    private static final By INVALID_EXP_ERR = By.cssSelector("a[href='#expiryDate-day']");
    private static final By ERROR_HDR = By.cssSelector("#header");

    private static final By ERROR_TITLE = By.cssSelector("#error-summary-title");

    private static final By PROVE_ID_A = By.cssSelector("a[href='prove-another-way']");
    private static final By PROVE_ID_R = By.cssSelector("#proveAnotherWayRadio-retry");
    private static final By PROVE_ID_A2 = By.cssSelector("#proveAnotherWayRadio");
    private static final By PROVE_ID_A3 = By.cssSelector("#proveAnotherWayRadio-retry");
    private static final String USER_DATA_DIRECTORY = "src/test/resources/Data/";
    private static final By UK_PASSPORT_STUB = By.cssSelector("#cri-link-ukPassport");
    private static final By STUB_JSON_RESP =
            By.xpath("//html[1]/body[1]/div[1]/main[1]/div[1]/div[1]/dl[2]/div[1]/dd[1]/pre[1]");
    private static final By COOKIE_BANNER_GOVUK =
            By.xpath("//*[@class='govuk-cookie-banner__heading govuk-heading-m']");
    private static final By GOVUK_HDR = By.cssSelector("#header");
    private static final By PASSPORTNBR_LBL = By.cssSelector("#passportNumber-label");
    private static final By SURNAME_LBL = By.xpath("//label[@id='surname-label']");
    private static final By FIRSTNAME_LBL = By.xpath("//label[@id='firstName-label']");
    private static final By MIDDLENAME_LBL = By.xpath("//label[@id='middleNames-label']");
    private static final By DOB_LBL = By.xpath("//legend[normalize-space()='Dyddiad geni']");
    private static final By DOB_HINT_LBL = By.xpath("//*[@id='dateOfBirth-hint']");
    private static final By DOB_DAY_LBL = By.xpath("//*[@for='dateOfBirth-day']");
    private static final By DOB_MONTH_LBL = By.xpath("//*[@for='dateOfBirth-month']");
    private static final By DOB_YEAR_LBL = By.xpath("//*[@for='dateOfBirth-year']");
    private static final By EXP_DATE_LBL =
            By.xpath("//legend[normalize-space()='Dyddiad dod i ben']");
    private static final By EXP_HINT_LBL = By.xpath("//*[@id='expiryDate-hint']");
    private static final By EXP_DAY_LBL = By.xpath("//*[@for='expiryDate-day']");
    private static final By EXP_MONTH_LBL = By.xpath("//*[@for='expiryDate-month']");
    private static final By EXP_YEAR_LBL = By.xpath("//*[@for='expiryDate-year']");
    private static final By SELECT_USER = By.xpath("//*[@id='test_data']");
    private static final By STRENGTH_SCORE = By.cssSelector("#strength");
    private static final By VALIDITY_SCORE = By.cssSelector("#validity");
    private static final By SUBMIT_AUTH = By.xpath("//input[@name='submit']");
    private static final By PASSPORT_HDR = By.cssSelector("#header");
    private static final By PASSPORT_HDRS = By.xpath("//*[@class='govuk-heading-xl']");
    private static final By TECH_ERR_HELP =
            By.xpath("//a[contains(text(),'Contact the GOV.UK One Login team (opens in a new ')]");
    private static final By JWT_EXP_HR = By.xpath("//*[@id='expHours']");
    private static final By KBV_HDR = By.xpath("//*[@class='govuk-heading-l']");
    private static final By JSONPayload = By.xpath("//*[@id=\"main-content\"]/div/details/div/pre");
    private static final Logger LOGGER = Logger.getLogger(EnterPassportDetailsPage.class.getName());
    private static final By FRAUD_HDRS = By.xpath("//*[@class='govuk-heading-xl']");
    private static final By JWT_CHECK_BOX = By.cssSelector("#vcExpiryFlg");

    public void waitForPageToLoad() {
        waitForElementVisible(PASSPORT_NUMBER_FIELD, 20);
    }

    public void enterPassportCriDetails(PassportSubject passportSubject) {
        waitForPageToLoad();
        populateField(PASSPORT_NUMBER_FIELD, passportSubject.getpassportNumber());
        populateField(SURNAME_FIELD, passportSubject.getsurname());
        populateField(FIRST_NAME_FIELD, passportSubject.getgivenName());
        populateField(DATE_OF_BIRTH_DAY_FIELD, passportSubject.getbirthDay());
        populateField(DATE_OF_BIRTH_MONTH_FIELD, passportSubject.getbirthMonth());
        populateField(DATE_OF_BIRTH_YEAR_FIELD, passportSubject.getbirthYear());
        populateField(EXPIRY_DATE_DAY_FIELD, passportSubject.getexpiryDay());
        populateDetailsInFields(EXPIRY_DATE_MONTH_FIELD, passportSubject.getexpiryMonth());
        populateField(EXPIRY_DATE_YEAR_FIELD, passportSubject.getexpiryYear());
        clickElement(CONTINUE_BUTTON);
    }

    public void invalidPassport() {
        BrowserUtils.waitForPageToLoad(10);
        Assert.assertEquals(
                "Your passport number should not include letters or symbols",
                getText(INVALID_PASSPORT_ERR));
    }

    public EnterPassportDetailsPage() {
        PageFactory.initElements(Driver.get(), this);
    }

    public void invalidsurname() {
        BrowserUtils.waitForPageToLoad(10);
        Assert.assertEquals(
                "Enter your surname as it appears on your passport", getText(INVALID_SURNAME_ERR));
    }

    public void invalidFirstName() {
        BrowserUtils.waitForPageToLoad(10);
        Assert.assertEquals(
                "Enter your first name as it appears on your passport",
                getText(INVALID_FIRSTNAME_ERR));
    }

    public void invalidDob() {
        BrowserUtils.waitForPageToLoad(10);
        Assert.assertEquals(
                "Enter your date of birth as it appears on your passport",
                getText(INVALID_DOB_ERR));
    }

    public void invalidExpdate() {
        BrowserUtils.waitForPageToLoad(10);
        Assert.assertEquals(
                "Enter the expiry date as it appears on your passport", getText(INVALID_EXP_ERR));
    }

    public void passportRetry(
            InvalidPassportSubject invalidPassportSubject, PassportSubject passportSubject) {
        waitForPageToLoad();
        populateField(PASSPORT_NUMBER_FIELD, invalidPassportSubject.getinvalidpassportNumber());
        populateField(SURNAME_FIELD, invalidPassportSubject.getinvalidsurname());
        populateField(FIRST_NAME_FIELD, invalidPassportSubject.getinvalidgivenName());
        populateField(DATE_OF_BIRTH_DAY_FIELD, invalidPassportSubject.getinvalidbirthDay());
        populateField(DATE_OF_BIRTH_MONTH_FIELD, invalidPassportSubject.getinvalidexpiryMonth());
        populateField(DATE_OF_BIRTH_YEAR_FIELD, invalidPassportSubject.getinvalidbirthYear());
        populateField(EXPIRY_DATE_DAY_FIELD, invalidPassportSubject.getinvalidexpiryDay());
        populateDetailsInFields(
                EXPIRY_DATE_MONTH_FIELD, invalidPassportSubject.getinvalidexpiryMonth());
        populateField(EXPIRY_DATE_YEAR_FIELD, invalidPassportSubject.getinvalidexpiryYear());
        clickElement(CONTINUE_BUTTON);
        Assert.assertEquals(
                "Check your details match what’s on your UK passport", getText(ERROR_HDR));
        clearText(PASSPORT_NUMBER_FIELD);
        clearText(SURNAME_FIELD);
        clearText(FIRST_NAME_FIELD);
        clearText(DATE_OF_BIRTH_DAY_FIELD);
        clearText(DATE_OF_BIRTH_MONTH_FIELD);
        clearText(DATE_OF_BIRTH_YEAR_FIELD);
        clearText(EXPIRY_DATE_MONTH_FIELD);
        clearText(EXPIRY_DATE_YEAR_FIELD);
        populateField(PASSPORT_NUMBER_FIELD, passportSubject.getpassportNumber());
        populateField(SURNAME_FIELD, passportSubject.getsurname());
        populateField(FIRST_NAME_FIELD, passportSubject.getgivenName());
        populateField(DATE_OF_BIRTH_DAY_FIELD, passportSubject.getbirthDay());
        populateField(DATE_OF_BIRTH_MONTH_FIELD, passportSubject.getbirthMonth());
        populateField(DATE_OF_BIRTH_YEAR_FIELD, passportSubject.getbirthYear());
        populateField(EXPIRY_DATE_DAY_FIELD, passportSubject.getexpiryDay());
        populateDetailsInFields(EXPIRY_DATE_MONTH_FIELD, passportSubject.getexpiryMonth());
        populateField(EXPIRY_DATE_YEAR_FIELD, passportSubject.getexpiryYear());
        clickElement(CONTINUE_BUTTON);
    }

    public void cannotproveidentity() {
        waitForElementVisible(ERROR_HDR, 20);
        Assert.assertEquals("Sorry, we cannot prove your identity", getText(ERROR_HDR));
    }

    public void invalidpassportRetry(
            InvalidPassportSubject invalidPassportSubject,
            InvalidPassportSubject invalidPassportSubject2) {
        waitForPageToLoad();
        populateField(PASSPORT_NUMBER_FIELD, invalidPassportSubject.getinvalidpassportNumber());
        populateField(SURNAME_FIELD, invalidPassportSubject.getinvalidsurname());
        populateField(FIRST_NAME_FIELD, invalidPassportSubject.getinvalidgivenName());
        populateField(DATE_OF_BIRTH_DAY_FIELD, invalidPassportSubject.getinvalidbirthDay());
        populateField(DATE_OF_BIRTH_MONTH_FIELD, invalidPassportSubject.getinvalidexpiryMonth());
        populateField(DATE_OF_BIRTH_YEAR_FIELD, invalidPassportSubject.getinvalidbirthYear());
        populateField(EXPIRY_DATE_DAY_FIELD, invalidPassportSubject.getinvalidexpiryDay());
        populateDetailsInFields(
                EXPIRY_DATE_MONTH_FIELD, invalidPassportSubject.getinvalidexpiryMonth());
        populateField(EXPIRY_DATE_YEAR_FIELD, invalidPassportSubject.getinvalidexpiryYear());
        clickElement(CONTINUE_BUTTON);
        Assert.assertEquals(
                "Check your details match what’s on your UK passport", getText(ERROR_HDR));
        clearText(PASSPORT_NUMBER_FIELD);
        clearText(SURNAME_FIELD);
        clearText(FIRST_NAME_FIELD);
        clearText(DATE_OF_BIRTH_DAY_FIELD);
        clearText(DATE_OF_BIRTH_MONTH_FIELD);
        clearText(DATE_OF_BIRTH_YEAR_FIELD);
        clearText(EXPIRY_DATE_MONTH_FIELD);
        clearText(EXPIRY_DATE_YEAR_FIELD);
        populateField(PASSPORT_NUMBER_FIELD, invalidPassportSubject2.getinvalidpassportNumber());
        populateField(SURNAME_FIELD, invalidPassportSubject2.getinvalidsurname());
        populateField(FIRST_NAME_FIELD, invalidPassportSubject2.getinvalidgivenName());
        populateField(DATE_OF_BIRTH_DAY_FIELD, invalidPassportSubject2.getinvalidbirthDay());
        populateField(DATE_OF_BIRTH_MONTH_FIELD, invalidPassportSubject2.getinvalidexpiryMonth());
        populateField(DATE_OF_BIRTH_YEAR_FIELD, invalidPassportSubject2.getinvalidbirthYear());
        populateField(EXPIRY_DATE_DAY_FIELD, invalidPassportSubject2.getinvalidexpiryDay());
        populateDetailsInFields(
                EXPIRY_DATE_MONTH_FIELD, invalidPassportSubject2.getinvalidexpiryMonth());
        populateField(EXPIRY_DATE_YEAR_FIELD, invalidPassportSubject2.getinvalidexpiryYear());
        clickElement(CONTINUE_BUTTON);
    }

    public void invalidPassportRetryFirst(InvalidPassportSubject invalidPassportSubject) {
        waitForPageToLoad();
        populateField(PASSPORT_NUMBER_FIELD, invalidPassportSubject.getinvalidpassportNumber());
        populateField(SURNAME_FIELD, invalidPassportSubject.getinvalidsurname());
        populateField(FIRST_NAME_FIELD, invalidPassportSubject.getinvalidgivenName());
        populateField(DATE_OF_BIRTH_DAY_FIELD, invalidPassportSubject.getinvalidbirthDay());
        populateField(DATE_OF_BIRTH_MONTH_FIELD, invalidPassportSubject.getinvalidexpiryMonth());
        populateField(DATE_OF_BIRTH_YEAR_FIELD, invalidPassportSubject.getinvalidbirthYear());
        populateField(EXPIRY_DATE_DAY_FIELD, invalidPassportSubject.getinvalidexpiryDay());
        populateDetailsInFields(
                EXPIRY_DATE_MONTH_FIELD, invalidPassportSubject.getinvalidexpiryMonth());
        populateField(EXPIRY_DATE_YEAR_FIELD, invalidPassportSubject.getinvalidexpiryYear());
        clickElement(CONTINUE_BUTTON);
    }

    public void invalidPassportRetrySecond(InvalidPassportSubject invalidPassportSubject) {
        waitForPageToLoad();
        clearText(PASSPORT_NUMBER_FIELD);
        clearText(SURNAME_FIELD);
        clearText(FIRST_NAME_FIELD);
        clearText(DATE_OF_BIRTH_DAY_FIELD);
        clearText(DATE_OF_BIRTH_MONTH_FIELD);
        clearText(DATE_OF_BIRTH_YEAR_FIELD);
        clearText(EXPIRY_DATE_MONTH_FIELD);
        clearText(EXPIRY_DATE_YEAR_FIELD);
        populateField(PASSPORT_NUMBER_FIELD, invalidPassportSubject.getinvalidpassportNumber());
        populateField(SURNAME_FIELD, invalidPassportSubject.getinvalidsurname());
        populateField(FIRST_NAME_FIELD, invalidPassportSubject.getinvalidgivenName());
        populateField(DATE_OF_BIRTH_DAY_FIELD, invalidPassportSubject.getinvalidbirthDay());
        populateField(DATE_OF_BIRTH_MONTH_FIELD, invalidPassportSubject.getinvalidexpiryMonth());
        populateField(DATE_OF_BIRTH_YEAR_FIELD, invalidPassportSubject.getinvalidbirthYear());
        populateField(EXPIRY_DATE_DAY_FIELD, invalidPassportSubject.getinvalidexpiryDay());
        populateDetailsInFields(
                EXPIRY_DATE_MONTH_FIELD, invalidPassportSubject.getinvalidexpiryMonth());
        populateField(EXPIRY_DATE_YEAR_FIELD, invalidPassportSubject.getinvalidexpiryYear());
        clickElement(CONTINUE_BUTTON);
    }

    public void proveidentityanotherway() {
        clickElement(PROVE_ID_A);
        clickElement(PROVE_ID_A2);
        clickElement(CONTINUE_BUTTON);
    }

    public void proveByPassport() {
        clickElement(PROVE_ID_A);
        clickElement(PROVE_ID_R);
        clickElement(CONTINUE_BUTTON);
    }

    public void passportRetryth(
            InvalidPassportSubject invalidPassportSubject, PassportSubject passportSubject) {
        waitForPageToLoad();
        populateField(PASSPORT_NUMBER_FIELD, invalidPassportSubject.getinvalidpassportNumber());
        populateField(SURNAME_FIELD, invalidPassportSubject.getinvalidsurname());
        populateField(FIRST_NAME_FIELD, invalidPassportSubject.getinvalidgivenName());
        populateField(DATE_OF_BIRTH_DAY_FIELD, invalidPassportSubject.getinvalidbirthDay());
        populateField(DATE_OF_BIRTH_MONTH_FIELD, invalidPassportSubject.getinvalidexpiryMonth());
        populateField(DATE_OF_BIRTH_YEAR_FIELD, invalidPassportSubject.getinvalidbirthYear());
        populateField(EXPIRY_DATE_DAY_FIELD, invalidPassportSubject.getinvalidexpiryDay());
        populateDetailsInFields(
                EXPIRY_DATE_MONTH_FIELD, invalidPassportSubject.getinvalidexpiryMonth());
        populateField(EXPIRY_DATE_YEAR_FIELD, invalidPassportSubject.getinvalidexpiryYear());
        clickElement(CONTINUE_BUTTON);
        Assert.assertEquals(
                "Check your details match what’s on your UK passport", getText(ERROR_HDR));
        clickElement(PROVE_ID_A);
        clickElement(PROVE_ID_R);
        clickElement(CONTINUE_BUTTON);
        clearText(PASSPORT_NUMBER_FIELD);
        clearText(SURNAME_FIELD);
        clearText(FIRST_NAME_FIELD);
        clearText(DATE_OF_BIRTH_DAY_FIELD);
        clearText(DATE_OF_BIRTH_MONTH_FIELD);
        clearText(DATE_OF_BIRTH_YEAR_FIELD);
        clearText(EXPIRY_DATE_MONTH_FIELD);
        clearText(EXPIRY_DATE_YEAR_FIELD);
        populateField(PASSPORT_NUMBER_FIELD, passportSubject.getpassportNumber());
        populateField(SURNAME_FIELD, passportSubject.getsurname());
        populateField(FIRST_NAME_FIELD, passportSubject.getgivenName());
        populateField(DATE_OF_BIRTH_DAY_FIELD, passportSubject.getbirthDay());
        populateField(DATE_OF_BIRTH_MONTH_FIELD, passportSubject.getbirthMonth());
        populateField(DATE_OF_BIRTH_YEAR_FIELD, passportSubject.getbirthYear());
        populateField(EXPIRY_DATE_DAY_FIELD, passportSubject.getexpiryDay());
        populateDetailsInFields(EXPIRY_DATE_MONTH_FIELD, passportSubject.getexpiryMonth());
        populateField(EXPIRY_DATE_YEAR_FIELD, passportSubject.getexpiryYear());
        clickElement(CONTINUE_BUTTON);
    }

    public void jsonResp(String jsonResp) throws IOException {
        JSONObject userDetailsObject =
                new JSONObject(
                        generateStringFromJsonPayloadResource(
                                USER_DATA_DIRECTORY, jsonResp.replaceAll(" ", "")));
        waitForElementVisible(STUB_JSON_RESP, 20);
        String ResponseJSON = getText(STUB_JSON_RESP);
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNode = objectMapper.readTree(ResponseJSON);
        JsonNode validityScr = jsonNode.get("validityScore");
        JsonNode strengthScr = jsonNode.get("strengthScore");
        String actualvalidatyScr = validityScr.asText();
        String actualstrengthScr = strengthScr.asText();
        String expectvalidatyScr = userDetailsObject.getString("validityScore");
        String expectstrengthScr = userDetailsObject.getString("strengthScore");
        Assert.assertEquals(expectvalidatyScr, actualvalidatyScr);
        Assert.assertEquals(expectstrengthScr, actualstrengthScr);
    }

    public void errorjsonResp(String jsonResp) throws IOException {
        waitForElementVisible(ERROR_HDR, 20);
        Assert.assertEquals("Sorry, we cannot prove your identity", getText(ERROR_HDR));
        clickElement(CONTINUE_BUTTON);
        BrowserUtils.waitForPageToLoad(10);
        JSONObject userDetailsObject =
                new JSONObject(
                        generateStringFromJsonPayloadResource(
                                USER_DATA_DIRECTORY, jsonResp.replaceAll(" ", "")));
        String ResponseJSON = getText(STUB_JSON_RESP);
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNode = objectMapper.readTree(ResponseJSON);
        JsonNode strengthScr = jsonNode.get("strengthScore");
        JsonNode validityScr = jsonNode.get("validityScore");
        JsonNode ciNode = jsonNode.get("ci");
        JsonNode insideciNode = ciNode.get(0);
        String Actualci = insideciNode.asText();
        String actualvalidatyScr = validityScr.asText();
        String actualstrengthScr = strengthScr.asText();
        String expectvalidatyScr = userDetailsObject.getString("validityScore");
        String expectstrengthScr = userDetailsObject.getString("strengthScore");
        String expectedci = userDetailsObject.getString("ci");
        Assert.assertEquals(expectvalidatyScr, actualvalidatyScr);
        Assert.assertEquals(expectstrengthScr, actualstrengthScr);
        Assert.assertEquals(expectedci, Actualci);
    }

    public void cookieupdatecy() {
        Cookie cookie = new Cookie("lng", "cy");
        Cookie cookie1 = new Cookie("lang", "cy");
        Driver.get().manage().addCookie(cookie);
        Driver.get().manage().addCookie(cookie1);
        Driver.get().navigate().refresh();
        BrowserUtils.waitFor(2);
    }

    public void updateLanguageCookiesDirect(final String language) {
        driver.manage().deleteCookieNamed("lng");
        Cookie cookie = new Cookie("lng", language);
        Driver.get().manage().addCookie(cookie);
        Driver.get().navigate().to(driver.getCurrentUrl());
        BrowserUtils.waitForPageToLoad(10);
    }

    public void welshLngGOVUKPage() {
        Assert.assertEquals("Cwcis ar GOV.UK One Login", getText(COOKIE_BANNER_GOVUK));
        Assert.assertEquals(
                "Dechrau profi pwy ydych chi gyda GOV.UK One Login", getText(GOVUK_HDR));
        Assert.assertEquals("Dechrau", getText(CONTINUE_BUTTON));
    }

    public void weleshLngPassportPage() {
        Assert.assertEquals(
                "Cwcis ar GOV.UK One Login",
                new YouHaveSignedInToYourGOVUKAccountPage().GOVUKbanner.getText());
        Assert.assertEquals(
                "Rhowch eich manylion yn union fel maent yn ymddangos ar eich pasbort y DU",
                new PassportPage().PassportPageHeader.getText());
        Assert.assertEquals("Rhif pasbort", getText(PASSPORTNBR_LBL));
        Assert.assertEquals("Cyfenw", getText(SURNAME_LBL));
        Assert.assertEquals("Enw cyntaf", getText(FIRSTNAME_LBL));
        Assert.assertEquals("Enwau canol", getText(MIDDLENAME_LBL));
        Assert.assertEquals("Dyddiad geni", getText(DOB_LBL));
        Assert.assertEquals("Er enghraifft, 5 9 1973", getText(DOB_HINT_LBL));
        Assert.assertEquals("Diwrnod", getText(DOB_DAY_LBL));
        Assert.assertEquals("Mis", getText(DOB_MONTH_LBL));
        Assert.assertEquals("Blwyddyn", getText(DOB_YEAR_LBL));
        Assert.assertEquals("Dyddiad dod i ben", getText(EXP_DATE_LBL));
        Assert.assertEquals("Er enghraifft, 27 5 2029", getText(EXP_HINT_LBL));
        Assert.assertEquals("Diwrnod", getText(EXP_DAY_LBL));
        Assert.assertEquals("Mis", getText(EXP_MONTH_LBL));
        Assert.assertEquals("Blwyddyn", getText(EXP_YEAR_LBL));
        Assert.assertEquals("Parhau", getText(CONTINUE_BUTTON));
    }

    public void weleshErrorInvalidPassport() {
        Assert.assertEquals(
                "Ni ddylai rhif eich pasbort gynnwys llythrennau na symbolau",
                getText(INVALID_PASSPORT_ERR));
    }

    public void weleshErrorInvalidFirstName() {
        Assert.assertEquals(
                "Rhowch eich enw cyntaf fel mae’n ymddangos ar eich pasbort",
                getText(INVALID_FIRSTNAME_ERR));
    }

    public void weleshErrorInvalidSurName() {
        Assert.assertEquals(
                "Rhowch eich cyfenw fel mae’n ymddangos ar eich pasbort",
                getText(INVALID_SURNAME_ERR));
    }

    public void weleshErrorInvaliddob() {
        Assert.assertEquals(
                "Rhowch eich dyddiad geni fel mae’n ymddangos ar eich pasbort",
                getText(INVALID_DOB_ERR));
    }

    public void weleshErrorInvalidexp() {
        Assert.assertEquals(
                "Rhowch y dyddiad dod i ben fel mae’n ymddangos ar eich pasbort",
                getText(INVALID_EXP_ERR));
    }

    public void weleshErrorcannotprove() {
        Assert.assertEquals("Mae’n ddrwg gennym, ni allwn brofi pwy ydych chi", getText(ERROR_HDR));
    }

    public void enterPassportDetails(String userName) throws IOException {
        JSONObject userDetailsObject =
                new JSONObject(
                        generateStringFromJsonPayloadResource(USER_DATA_DIRECTORY, userName));
        waitForPageToLoad();
        populateField(PASSPORT_NUMBER_FIELD, userDetailsObject.getString("passportNumber"));
        populateField(SURNAME_FIELD, userDetailsObject.getString("surname"));
        populateField(FIRST_NAME_FIELD, userDetailsObject.getString("firstName"));
        populateField(DATE_OF_BIRTH_DAY_FIELD, userDetailsObject.getString("dobDay"));
        populateField(DATE_OF_BIRTH_MONTH_FIELD, userDetailsObject.getString("dobMonth"));
        populateField(DATE_OF_BIRTH_YEAR_FIELD, userDetailsObject.getString("dobYear"));
        populateField(EXPIRY_DATE_DAY_FIELD, userDetailsObject.getString("expDay"));
        populateField(EXPIRY_DATE_MONTH_FIELD, userDetailsObject.getString("expMonth"));
        populateField(EXPIRY_DATE_YEAR_FIELD, userDetailsObject.getString("expYear"));
        clickElement(CONTINUE_BUTTON);
    }

    public void enterStubPassportDetails(String passportSubject) throws IOException {
        JSONObject userDetailsObject =
                new JSONObject(
                        generateStringFromJsonPayloadResource(
                                USER_DATA_DIRECTORY, passportSubject));
        waitForElementVisible(SELECT_USER, 20);
        Select select = new Select(getCurrentDriver().findElement(SELECT_USER));
        select.selectByValue("Kenneth Decerqueira (Valid Experian) Passport");
        populateField(STRENGTH_SCORE, userDetailsObject.getString("Strength"));
        populateField(VALIDITY_SCORE, userDetailsObject.getString("Validity"));
        clickElement(JWT_CHECK_BOX);
        new IpvCoreFrontPageArchive().JWT_EXP_HR.clear();
        new IpvCoreFrontPageArchive().JWT_EXP_HR.sendKeys("4");
        clickElement(SUBMIT_AUTH);
    }

    public void enterNoStubPassportDetails() {
        clickElement(SUBMIT_AUTH);
    }

    public void weleshTechError() {
        Assert.assertEquals("Mae’n ddrwg gennym, mae problem", getText(ERROR_HDR));
    }

    public void clickBrowserButton() {

        Driver.get().navigate().back();
    }

    public void userIsOnPassportcri() {
        Assert.assertEquals("UK Passport (Stub)", getText(PASSPORT_HDRS));
    }

    public void backButtonErrPage() {
        Assert.assertEquals("Sorry, you cannot go back", getText(ERROR_HDR));
        clickElement(CONTINUE_BUTTON);
    }

    public void userIsOnAddresscri() {
        Assert.assertEquals("Address (Stub)", getText(PASSPORT_HDRS));
    }

    public void userIsOnKbvcri() {
        Assert.assertEquals("Answer security questions", getText(KBV_HDR));
    }

    public void userIsOnFraudcri() {
        Assert.assertEquals("Fraud Check (Stub)", getText(FRAUD_HDRS));
    }

    public void userIsOnPassportcris() {
        Assert.assertEquals(
                "Enter your details exactly as they appear on your UK passport",
                getText(PASSPORT_HDR));
    }

    public void clickOnlySubAuths() {
        clickElement(CONTINUE_BUTTON);
    }

    public void enterPassportCriDetail(String userName) throws IOException {
        waitForPageToLoad();
        JSONObject userDetailsObject =
                new JSONObject(
                        generateStringFromJsonPayloadResource(USER_DATA_DIRECTORY, userName));
        populateField(PASSPORT_NUMBER_FIELD, userDetailsObject.getString("passportNumber"));
        populateField(SURNAME_FIELD, userDetailsObject.getString("surname"));
        populateField(FIRST_NAME_FIELD, userDetailsObject.getString("firstName"));
        populateField(DATE_OF_BIRTH_DAY_FIELD, userDetailsObject.getString("dobDay"));
        populateField(DATE_OF_BIRTH_MONTH_FIELD, userDetailsObject.getString("dobMonth"));
        populateField(DATE_OF_BIRTH_YEAR_FIELD, userDetailsObject.getString("dobYear"));
        populateField(EXPIRY_DATE_DAY_FIELD, userDetailsObject.getString("expDay"));
        populateField(EXPIRY_DATE_MONTH_FIELD, userDetailsObject.getString("expMonth"));
        populateField(EXPIRY_DATE_YEAR_FIELD, userDetailsObject.getString("expYear"));
        clickElement(CONTINUE_BUTTON);
    }

    public void continueEnteringPassportDetails() {
        clickElement(PROVE_ID_A);
        clickElement(PROVE_ID_A2);
        clickElement(CONTINUE_BUTTON);
    }

    public void oneLoginBrandingChanges() {
        Assert.assertEquals(
                "Contact the GOV.UK One Login team (opens in a new tab)", getText(TECH_ERR_HELP));
    }

    public void enterStubNoExpPassportDetails(String passportSubject) throws IOException {
        JSONObject userDetailsObject =
                new JSONObject(
                        generateStringFromJsonPayloadResource(
                                USER_DATA_DIRECTORY, passportSubject));
        waitForElementVisible(SELECT_USER, 20);
        Select select = new Select(getCurrentDriver().findElement(SELECT_USER));
        select.selectByValue("Kenneth Decerqueira (Valid Experian) Passport");
        populateField(STRENGTH_SCORE, userDetailsObject.getString("Strength"));
        populateField(VALIDITY_SCORE, userDetailsObject.getString("Validity"));
        clickElement(SUBMIT_AUTH);
    }

    public void enterStubExpPassportDetails(String passportSubject) throws IOException {
        JSONObject userDetailsObject =
                new JSONObject(
                        generateStringFromJsonPayloadResource(
                                USER_DATA_DIRECTORY, passportSubject));
        waitForElementVisible(SELECT_USER, 20);
        Select select = new Select(getCurrentDriver().findElement(SELECT_USER));
        select.selectByValue("Kenneth Decerqueira (Valid Experian) Passport");
        populateField(STRENGTH_SCORE, userDetailsObject.getString("Strength"));
        populateField(VALIDITY_SCORE, userDetailsObject.getString("Validity"));
        clickElement(JWT_CHECK_BOX);
        new IpvCoreFrontPageArchive().JWT_EXP_HR.clear();
        new IpvCoreFrontPageArchive().JWT_EXP_HR.sendKeys("2");
        clickElement(SUBMIT_AUTH);
    }

    public void userOnPasspoirtCriPage() {
        Assert.assertEquals("UK Passport (Stub)", getText(PASSPORT_HDRS));
    }

    public void proveidentityanother() {
        waitForElementVisible(KBV_HDR, 20);
        Assert.assertEquals("Continue proving your identity online", getText(KBV_HDR));
    }
}
