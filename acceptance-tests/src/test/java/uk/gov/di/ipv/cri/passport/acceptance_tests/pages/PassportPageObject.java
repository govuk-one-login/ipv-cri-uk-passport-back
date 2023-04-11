package uk.gov.di.ipv.cri.passport.acceptance_tests.pages;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import org.apache.commons.lang3.StringUtils;
import org.junit.Assert;
import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;
import org.openqa.selenium.support.PageFactory;
import uk.gov.di.ipv.cri.passport.acceptance_tests.service.ConfigurationService;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.BrowserUtils;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.Driver;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.TestDataCreator;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.TestInput;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import static org.junit.Assert.fail;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.ipv.cri.passport.acceptance_tests.pages.Headers.IPV_CORE_STUB;

public class PassportPageObject extends UniversalSteps {

    private final ConfigurationService configurationService;
    private static final Logger LOGGER = Logger.getLogger(PassportPageObject.class.getName());

    // Should be separate stub page

    @FindBy(xpath = "//*[@id=\"main-content\"]/p/a/button")
    public WebElement visitCredentialIssuers;

    @FindBy(xpath = "//*[@value=\"Passport CRI Dev\"]")
    public WebElement passportCRIDev;

    @FindBy(xpath = "//*[@value=\"Build Passport\"]")
    public WebElement passportCRIBuild;

    @FindBy(xpath = "//*[@value=\"Staging Passport\"]")
    public WebElement passportCRIStaging;

    @FindBy(xpath = "//*[@value=\"Integration Passport\"]")
    public WebElement passportCRIIntegration;

    @FindBy(id = "rowNumber")
    public WebElement selectRow;

    @FindBy(xpath = "//*[@id=\"main-content\"]/div/details/div/pre")
    public WebElement JSONPayload;

    @FindBy(xpath = "//*[@id=\"main-content\"]/div/details")
    public WebElement errorResponse;

    @FindBy(xpath = "//*[@id=\"main-content\"]/div/details/summary/span")
    public WebElement viewResponse;

    @FindBy(xpath = "//*[@id=\"main-content\"]/form[2]/div/button")
    public WebElement searchButton;

    @FindBy(xpath = "//*[@id=\"main-content\"]/form[2]/div/button")
    public WebElement goToPassportCRIButton;

    // ---------------------

    @FindBy(className = "error-summary")
    public WebElement errorSummary;

    @FindBy(xpath = "//*[@class='govuk-notification-banner__content']")
    public WebElement userNotFoundInThirdPartyBanner;

    @FindBy(xpath = "//*[@id=\"main-content\"]/div/div/div/a")
    public WebElement proveAnotherWay;

    @FindBy(id = "proveAnotherWayRadio")
    public WebElement proveAnotherWayRadio;

    @FindBy(id = "govuk-notification-banner-title")
    public WebElement errorText;

    @FindBy(xpath = "//*[@id=\"main-content\"]/div/div/div[1]/div[2]/p[1]")
    public WebElement thereWasAProblemFirstSentence;

    @FindBy(xpath = "//*[@id=\"main-content\"]/div/div/p")
    public WebElement pageDescriptionHeading;

    @FindBy(xpath = "/html/body/div[2]/div/p/strong")
    public WebElement betaBanner;

    @FindBy(className = "govuk-phase-banner__text")
    public WebElement betaBannerText;

    @FindBy(id = "error-summary-title")
    public WebElement errorSummaryTitle;

    @FindBy(id = "passportNumber")
    public WebElement passportNumber;

    @FindBy(id = "surname")
    public WebElement LastName;

    @FindBy(id = "firstName")
    public WebElement FirstName;

    @FindBy(id = "middleNames")
    public WebElement MiddleNames;

    @FindBy(id = "dateOfBirth-day")
    public WebElement birthDay;

    @FindBy(id = "dateOfBirth-month")
    public WebElement birthMonth;

    @FindBy(id = "dateOfBirth-year")
    public WebElement birthYear;

    @FindBy(id = "expiryDate-day")
    public WebElement validToDay;

    @FindBy(id = "expiryDate-month")
    public WebElement validToMonth;

    @FindBy(id = "expiryDate-year")
    public WebElement validToYear;

    @FindBy(xpath = "//button[@class='govuk-button button']")
    public WebElement Continue;

    @FindBy(id = "header")
    public WebElement pageHeader;

    // Error summary items

    @FindBy(
            xpath =
                    "//*[@class='govuk-error-summary error-summary']//*[@class='govuk-error-summary__body']//*[@class='govuk-list govuk-error-summary__list']//*[contains(@href,'-day')]")
    public WebElement InvalidDOBErrorInSummary;

    @FindBy(
            xpath =
                    "//*[@class='govuk-error-summary error-summary']//*[@class='govuk-error-summary__body']//*[@class='govuk-list govuk-error-summary__list']//*[contains(@href,'passportNumber')]")
    public WebElement InvalidPassportErrorInSummary;

    @FindBy(
            xpath =
                    "//*[@class='govuk-error-summary error-summary']//*[@class='govuk-error-summary__body']//*[@class='govuk-list govuk-error-summary__list']//*[contains(@href,'#surname')]")
    public WebElement InvalidLastNameErrorInSummary;

    @FindBy(
            xpath =
                    "//*[@class='govuk-error-summary error-summary']//*[@class='govuk-error-summary__body']//*[@class='govuk-list govuk-error-summary__list']//*[contains(@href,'#firstName')]")
    public WebElement InvalidFirstNameErrorInSummary;

    @FindBy(
            xpath =
                    "//*[@class='govuk-error-summary error-summary']//*[@class='govuk-error-summary__body']//*[@class='govuk-list govuk-error-summary__list']//*[contains(@href,'#middleNames')]")
    public WebElement InvalidMiddleNamesErrorInSummary;

    @FindBy(
            xpath =
                    "//*[@class='govuk-error-summary error-summary']//*[@class='govuk-error-summary__body']//*[@class='govuk-list govuk-error-summary__list']//*[contains(@href,'#expiryDate-day')]")
    public WebElement InvalidValidToDateErrorInSummary;

    // -------------------------

    // Field errors

    @FindBy(id = "dateOfBirth-error")
    public WebElement InvalidDateOfBirthFieldError;

    @FindBy(id = "surname-error")
    public WebElement InvalidLastNameFieldError;

    @FindBy(id = "firstName-error")
    public WebElement InvalidFirstNameFieldError;

    @FindBy(id = "middleNames-error")
    public WebElement InvalidMiddleNamesFieldError;

    @FindBy(id = "expiryDate-error")
    public WebElement InvalidValidToDateFieldError;

    @FindBy(id = "passportNumber-error")
    public WebElement PassportNumberFieldError;

    // ------------------------

    // --- Hints ---
    @FindBy(id = "dateOfBirth-hint")
    public WebElement dateOfBirthHint;

    @FindBy(id = "passportNumber-hint")
    public WebElement passportNumberHint;

    @FindBy(id = "firstName-hint")
    public WebElement firstNameHint;

    @FindBy(id = "middleNames-hint")
    public WebElement middleNameHint;

    @FindBy(id = "expiryDate-hint")
    public WebElement validToHint;

    // --- Legend text ---
    @FindBy(xpath = "//*[@id=\"dateOfBirth-fieldset\"]/legend")
    public WebElement dateOfBirthLegend;

    @FindBy(xpath = "//*[@id=\"expiryDate-fieldset\"]/legend")
    public WebElement validToLegend;

    // --- Label text ---
    @FindBy(id = "passportNumber-label")
    public WebElement passportNumberFieldLabel;

    @FindBy(xpath = "//*[@class='govuk-back-link']")
    public WebElement back;

    public PassportPageObject() {
        this.configurationService = new ConfigurationService(System.getenv("ENVIRONMENT"));
        PageFactory.initElements(Driver.get(), this);
        TestDataCreator.createDefaultResponses();
    }

    // Should be in stub page

    public void navigateToIPVCoreStub() {
        String coreStubUrl = configurationService.getCoreStubUrl(true);
        Driver.get().get(coreStubUrl);
        waitForTextToAppear(IPV_CORE_STUB);
    }

    public void navigateToPassportCRIOnTestEnv() {
        visitCredentialIssuers.click();
        String passportCRITestEnvironment = configurationService.getPassportCRITestEnvironment();
        LOGGER.info("passportCRITestEnvironment = " + passportCRITestEnvironment);
        if (passportCRITestEnvironment.equalsIgnoreCase("Dev")) {
            passportCRIDev.click();
        } else if (passportCRITestEnvironment.equalsIgnoreCase("Build")) {
            passportCRIBuild.click();
        } else if (passportCRITestEnvironment.equalsIgnoreCase("Staging")) {
            passportCRIStaging.click();
        } else if (passportCRITestEnvironment.equalsIgnoreCase("Integration")) {
            passportCRIIntegration.click();
        } else {
            LOGGER.info("No test environment is set");
        }
    }

    public void searchForUATUser(String number) {
        assertURLContains(
                "credential-issuer?cri="
                        + System.getenv("ENVIRONMENT").toLowerCase()
                        + "-passport");
        selectRow.sendKeys(number);
        searchButton.click();
    }

    public void navigateToPassportResponse(String validOrInvalid) {
        assertURLContains("callback");
        if ("Invalid".equalsIgnoreCase(validOrInvalid)) {
            errorResponse.click();
        } else {
            viewResponse.click();
        }
    }

    public void navigateToPassportCRI() {
        goToPassportCRIButton.click();
    }

    // ------------------

    // Should be seperate page

    public void betaBanner() {
        betaBanner.isDisplayed();
    }

    public void betaBannerSentence(String expectedText) {
        Assert.assertEquals(expectedText, betaBannerText.getText());
    }

    public void passportPageURLValidation() {
        assertURLContains("review-p");
    }

    public void assertUserRoutedToIpvCore() {
        assertPageTitle("IPV Core Stub - GOV.UK");
    }

    public void assertUserRoutedToIpvCoreErrorPage() {
        String coreStubUrl = configurationService.getCoreStubUrl(false);
        String expUrl =
                coreStubUrl
                        + "/callback?error=access_denied&error_description=Authorization+permission+denied";
        String actUrl = Driver.get().getCurrentUrl();
        LOGGER.info("expectedUrl = " + expUrl);
        LOGGER.info("actualUrl = " + actUrl);
        Assert.assertEquals(actUrl, expUrl);
    }

    public void jsonErrorResponse(String expectedErrorDescription, String expectedErrorStatusCode)
            throws JsonProcessingException {
        String result = JSONPayload.getText();
        LOGGER.info("result = " + result);

        JsonNode insideError = getJsonNode(result, "errorObject");
        LOGGER.info("insideError = " + insideError);

        JsonNode errorDescription = insideError.get("description");
        JsonNode statusCode = insideError.get("httpstatusCode");
        String ActualErrorDescription = insideError.get("description").asText();
        String ActualStatusCode = insideError.get("httpstatusCode").asText();

        LOGGER.info("errorDescription = " + errorDescription);
        LOGGER.info("statusCode = " + statusCode);
        LOGGER.info("testErrorDescription = " + expectedErrorDescription);
        LOGGER.info("testStatusCode = " + expectedErrorStatusCode);

        Assert.assertEquals(expectedErrorDescription, ActualErrorDescription);
        Assert.assertEquals(expectedErrorStatusCode, ActualStatusCode);
    }

    public void checkScoreInStubIs(String validityScore, String strengthScore) throws IOException {
        scoreIs(validityScore, strengthScore, JSONPayload.getText());
    }

    public void scoreIs(String validityScore, String strengthScore, String jsonPayloadText)
            throws IOException {
        String result = jsonPayloadText;
        LOGGER.info("result = " + result);
        JsonNode vcNode = getJsonNode(result, "vc");
        List<JsonNode> evidence = getListOfNodes(vcNode, "evidence");

        String ValidityScore = evidence.get(0).get("validityScore").asText();
        assertEquals(ValidityScore, validityScore);

        String StrengthScore = evidence.get(0).get("strengthScore").asText();
        assertEquals(StrengthScore, strengthScore);
    }

    public void userNotFoundInThirdPartyErrorIsDisplayed() {
        Assert.assertTrue(userNotFoundInThirdPartyBanner.isDisplayed());
        LOGGER.info(userNotFoundInThirdPartyBanner.getText());
    }

    public void userEntersData(String passportSubjectScenario) {
        TestInput passportSubject =
                TestDataCreator.getPassportTestUserFromMap(passportSubjectScenario);
        passportNumber.sendKeys(passportSubject.getPassportNumber());
        birthDay.sendKeys(passportSubject.getBirthDay());
        birthMonth.sendKeys(passportSubject.getBirthMonth());
        birthYear.sendKeys(passportSubject.getBirthYear());

        LastName.sendKeys(passportSubject.getLastName());
        FirstName.sendKeys(passportSubject.getFirstName());
        validToDay.sendKeys(passportSubject.getValidToDay());
        validToMonth.sendKeys(passportSubject.getValidToMonth());
        validToYear.sendKeys(passportSubject.getValidToYear());
    }

    // Why is this invalid
    public void userEntersInvalidPassportDetails() {
        PassportPageObject passportPage = new PassportPageObject();
        passportPage.passportNumber.sendKeys("123456789");
        passportPage.LastName.sendKeys("Testlastname");
        passportPage.FirstName.sendKeys("Testfirstname");
        passportPage.birthDay.sendKeys("11");
        passportPage.birthMonth.sendKeys("10");
        passportPage.birthYear.sendKeys("1962");
        passportPage.validToDay.sendKeys("01");
        passportPage.validToMonth.sendKeys("01");
        passportPage.validToYear.sendKeys("2030");

        BrowserUtils.waitForPageToLoad(10);
    }

    public void enterInvalidLastAndFirstName() {
        PassportPageObject passportPageObject = new PassportPageObject();
        passportPageObject.LastName.sendKeys("Parker!");
        passportPageObject.FirstName.sendKeys("Peter@@!");
        passportPageObject.MiddleNames.sendKeys("@@@@@@@");
    }

    public void enterBirthYear(String day, String month, String year) {
        PassportPageObject passportPageObject = new PassportPageObject();
        passportPageObject.birthDay.clear();
        passportPageObject.birthDay.click();
        passportPageObject.birthDay.sendKeys(day);
        passportPageObject.birthMonth.clear();
        passportPageObject.birthMonth.click();
        passportPageObject.birthMonth.sendKeys(month);
        passportPageObject.birthYear.clear();
        passportPageObject.birthYear.click();
        passportPageObject.birthYear.sendKeys(year);
    }

    public void enterValidToDate(String day, String month, String year) {
        PassportPageObject passportPageObject = new PassportPageObject();
        passportPageObject.validToDay.clear();
        passportPageObject.validToDay.click();
        passportPageObject.validToDay.sendKeys(day);
        passportPageObject.validToMonth.clear();
        passportPageObject.validToMonth.click();
        passportPageObject.validToMonth.sendKeys(month);
        passportPageObject.validToYear.clear();
        passportPageObject.validToYear.click();
        passportPageObject.validToYear.sendKeys(year);
    }

    public void enterPassportNumber(String passportNumber) {
        PassportPageObject passportPage = new PassportPageObject();
        passportPage.passportNumber.clear();
        passportPage.passportNumber.click();
        passportPage.passportNumber.sendKeys(passportNumber);
    }

    public void userReEntersDataAsPassportSubject(String passportSubjectScenario) {
        TestInput passportSubject =
                TestDataCreator.getPassportTestUserFromMap(passportSubjectScenario);

        passportNumber.clear();
        LastName.clear();
        FirstName.clear();
        MiddleNames.clear();
        birthDay.clear();
        birthMonth.clear();
        birthYear.clear();
        validToDay.clear();
        validToMonth.clear();
        validToYear.clear();
        passportNumber.sendKeys(passportSubject.getPassportNumber());
        LastName.sendKeys(passportSubject.getLastName());
        FirstName.sendKeys(passportSubject.getFirstName());
        if (null != passportSubject.getMiddleNames()) {
            MiddleNames.sendKeys(passportSubject.getMiddleNames());
        }
        birthDay.sendKeys(passportSubject.getBirthDay());
        birthMonth.sendKeys(passportSubject.getBirthMonth());
        birthYear.sendKeys(passportSubject.getBirthYear());
        validToDay.sendKeys(passportSubject.getValidToDay());
        validToMonth.sendKeys(passportSubject.getValidToMonth());
        validToYear.sendKeys(passportSubject.getValidToYear());
    }

    public void assertInvalidDoBInErrorSummary(String expectedText) {
        Assert.assertEquals(expectedText, InvalidDOBErrorInSummary.getText());
    }

    public void assertInvalidDoBOnField(String expectedText) {
        Assert.assertEquals(
                expectedText, InvalidDateOfBirthFieldError.getText().trim().replace("\n", ""));
    }

    public void assertInvalidValidToDateInErrorSummary(String expectedText) {
        Assert.assertEquals(expectedText, InvalidValidToDateErrorInSummary.getText());
    }

    public void assertInvalidValidToDateOnField(String expectedText) {
        Assert.assertEquals(
                expectedText, InvalidValidToDateFieldError.getText().trim().replace("\n", ""));
    }

    public void assertInvalidPassportNumberInErrorSummary(String expectedText) {
        Assert.assertEquals(expectedText, InvalidPassportErrorInSummary.getText());
    }

    public void assertInvalidPassportNumberOnField(String expectedText) {
        Assert.assertEquals(
                expectedText, PassportNumberFieldError.getText().trim().replace("\n", ""));
    }

    public void assertInvalidLastNameInErrorSummary(String expectedText) {
        Assert.assertEquals(expectedText, InvalidLastNameErrorInSummary.getText());
    }

    public void assertInvalidLastNameOnField(String expectedText) {
        Assert.assertEquals(
                expectedText, InvalidLastNameFieldError.getText().trim().replace("\n", ""));
    }

    public void assertInvalidFirstNameInErrorSummary(String expectedText) {
        Assert.assertEquals(expectedText, InvalidFirstNameErrorInSummary.getText());
    }

    public void assertInvalidFirstNameOnField(String expectedText) {
        Assert.assertEquals(
                expectedText, InvalidFirstNameFieldError.getText().trim().replace("\n", ""));
    }

    public void assertInvalidMiddleNameInErrorSummary(String expectedText) {
        Assert.assertEquals(expectedText, InvalidMiddleNamesErrorInSummary.getText());
    }

    public void assertInvalidMiddleNameOnField(String expectedText) {
        Assert.assertEquals(
                expectedText, InvalidMiddleNamesFieldError.getText().trim().replace("\n", ""));
    }

    public void ciInVC(String ci) throws IOException {
        String result = JSONPayload.getText();
        LOGGER.info("result = " + result);
        JsonNode vcNode = getJsonNode(result, "vc");
        JsonNode evidenceNode = vcNode.get("evidence");

        List<String> cis = getCIsFromEvidence(evidenceNode);

        if (StringUtils.isNotEmpty(ci)) {
            if (cis.size() > 0) {
                LOGGER.info("HELP " + Arrays.toString(cis.toArray()) + "    " + ci);
                assertTrue(cis.contains(ci));
            } else {
                fail("No CIs found");
            }
        }
    }

    public void assertDocumentNumberInVc(String documentNumber) throws IOException {
        String result = JSONPayload.getText();
        LOGGER.info("result = " + result);
        JsonNode vcNode = getJsonNode(result, "vc");
        String passportNumber = getDocumentNumberFromVc(vcNode);
        assertEquals(documentNumber, passportNumber);
    }

    public void validateErrorPageHeading() {
        String expectedHeading = "Sorry, there is a problem";
        String actualHeading = pageHeader.getText();
        if (expectedHeading.equals(actualHeading)) {
            LOGGER.info("Pass : Sorry, there is a problem page is displayed");
        } else {
            fail("Fail: Error page not displayed");
        }
    }

    public void assertPageTitle(String expTitle) {
        String actualTitle = Driver.get().getTitle();

        LOGGER.info("Page title: " + actualTitle);
        Assert.assertEquals(expTitle, actualTitle);
    }

    public void assertPageHeading(String expectedText) {
        Assert.assertEquals(expectedText, pageHeader.getText().split("\n")[0]);
    }

    public void assertProveAnotherWayLinkText(String expectedText) {
        Assert.assertEquals(expectedText, getParent(proveAnotherWay).getText());
    }

    public void assertErrorPrefix(String expectedText) {
        Assert.assertEquals(expectedText, errorText.getText());
    }

    public void assertFirstLineOfUserNotFoundText(String expectedText) {
        Assert.assertEquals(expectedText, userNotFoundInThirdPartyBanner.getText().split("\n")[0]);
    }

    public void youWillBeAbleToFindSentence(String expectedText) {
        Assert.assertEquals(expectedText, thereWasAProblemFirstSentence.getText());
    }

    public void assertPageSourceContains(String expectedText) {
        assert (Driver.get().getPageSource().contains(expectedText));
    }

    public void assertLastNameLabelText(String expectedText) {
        Assert.assertEquals(expectedText, getLabel(getParent(LastName)).getText());
    }

    public void assertGivenNameLegendText(String expectedText) {
        Assert.assertEquals(
                expectedText,
                FirstName.findElement(By.xpath("./../../.."))
                        .findElement(By.tagName("legend"))
                        .getText());
    }

    public void assertMiddleNameLabelText(String expectedText) {
        Assert.assertEquals(expectedText, getLabel(getParent(MiddleNames)).getText());
    }

    public void assertGivenNameDescription(String expectedText) {
        Assert.assertEquals(
                expectedText, getLabel(firstNameHint.findElement(By.xpath("./../.."))).getText());
    }

    public void assertGivenNameHint(String expectedText) {
        Assert.assertEquals(expectedText, firstNameHint.getText());
    }

    public void assertMiddleNameHint(String expectedText) {
        Assert.assertEquals(expectedText, middleNameHint.getText());
    }

    public void assertDateOfBirthLegendText(String expectedText) {
        Assert.assertEquals(expectedText, dateOfBirthLegend.getText());
    }

    public void assertDateOfBirthHintText(String expectedText) {
        Assert.assertEquals(expectedText, dateOfBirthHint.getText());
    }

    public void assertBirthDayLabelText(String expectedText) {
        Assert.assertEquals(expectedText, getLabel(getParent(birthDay)).getText());
    }

    public void assertBirthMonthLabelText(String expectedText) {
        Assert.assertEquals(expectedText, getLabel(getParent(birthMonth)).getText());
    }

    public void assertBirthYearLabelText(String expectedText) {
        Assert.assertEquals(expectedText, getLabel(getParent(birthYear)).getText());
    }

    public void assertValidToHintText(String expectedText) {
        Assert.assertEquals(expectedText, validToHint.getText());
    }

    public void assertPassportNumberLabelText(String expectedText) {
        Assert.assertEquals(expectedText, passportNumberFieldLabel.getText());
    }

    public void assertPassportNumberHintText(String expectedText) {
        Assert.assertEquals(expectedText, passportNumberHint.getText());
    }

    public void assertPageDescription(String expectedText) {
        Assert.assertEquals(expectedText, pageDescriptionHeading.getText());
    }

    public void assertValidToLegend(String expectedText) {
        Assert.assertEquals(expectedText, validToLegend.getText());
    }

    public void assertErrorSummaryText(String expectedText) {
        Assert.assertEquals(expectedText, errorSummaryTitle.getText());
    }

    public void assertCTATextAs(String expectedText) {
        assertEquals(Continue.getText(), expectedText);
    }

    private List<String> getCIsFromEvidence(JsonNode evidenceNode) throws IOException {
        ObjectReader objectReader =
                new ObjectMapper().readerFor(new TypeReference<List<JsonNode>>() {});
        List<JsonNode> evidence = objectReader.readValue(evidenceNode);

        List<String> cis =
                getListOfNodes(evidence.get(0), "ci").stream()
                        .map(JsonNode::asText)
                        .collect(Collectors.toList());
        return cis;
    }

    private JsonNode getJsonNode(String result, String vc) throws JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNode = objectMapper.readTree(result);
        return jsonNode.get(vc);
    }

    private String getDocumentNumberFromVc(JsonNode vcNode) throws IOException {
        JsonNode credentialSubject = vcNode.findValue("credentialSubject");
        List<JsonNode> evidence = getListOfNodes(credentialSubject, "passport");

        String passportNumber = evidence.get(0).get("documentNumber").asText();
        return passportNumber;
    }

    private List<JsonNode> getListOfNodes(JsonNode vcNode, String evidence) throws IOException {
        JsonNode evidenceNode = vcNode.get(evidence);

        ObjectReader objectReader =
                new ObjectMapper().readerFor(new TypeReference<List<JsonNode>>() {});
        return objectReader.readValue(evidenceNode);
    }

    private WebElement getParent(WebElement webElement) {
        return webElement.findElement(By.xpath("./.."));
    }

    private WebElement getLabel(WebElement webElement) {
        return webElement.findElement(By.tagName("label"));
    }
}
