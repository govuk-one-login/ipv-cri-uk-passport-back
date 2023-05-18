package uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.json.JSONObject;
import org.junit.Assert;
import org.openqa.selenium.By;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.UtilitiesFromIpvRepo.BrowserUtils;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.UtilitiesFromIpvRepo.ConfigurationReader;

import java.io.IOException;

public class IpvCheckResultsPage extends GlobalPage {

    private static final By PAGE_HEADER = By.cssSelector("#header");
    private static final By CONTINUE = By.cssSelector("#submitButton");
    private static final String USER_DATA_DIRECTORY = "src/test/resources/data/";
    private static final By VERIFY_CREDENTIALS =
            By.xpath("//div[2]//dd[1]//details[1]//summary[1]//span[1]");
    private static final By VERIFY_CREDENTIAL4 =
            By.xpath("//div[4]//dd[1]//details[1]//summary[1]//span[1]");
    private static final By STUB_RESP_JSON =
            By.xpath(
                    "//html[1]/body[1]/div[1]/main[1]/div[3]/div[1]/dl[1]/div[2]/dd[1]/details[1]/div[1]/pre[1]/code[1]");
    private static final By STUB_RESP_JSON4 =
            By.xpath(
                    "//html[1]/body[1]/div[1]/main[1]/div[3]/div[1]/dl[1]/div[4]/dd[1]/details[1]/div[1]/pre[1]/code[1]");
    private static final By CONTINUE_BUTTON = By.xpath("//button[@name='submitButton']");
    private static final By SUCCESS_HDR = By.cssSelector("#header");
    private static final By REUSE_TXT =
            By.xpath("//*[contains(text(),'If you have not signed in to GOV.UK One Login in a')]");

    public static void mobileStubSuccess(String jsonResp) throws IOException {
        Assert.assertEquals("Continue to the service you want to use", getText(SUCCESS_HDR));
        clickElement(CONTINUE_BUTTON);
        BrowserUtils.waitForPageToLoad(20);
        JSONObject userDetailsObject =
                new JSONObject(
                        generateStringFromJsonPayloadResource(
                                USER_DATA_DIRECTORY, jsonResp.replaceAll(" ", "")));
        clickElement(VERIFY_CREDENTIALS);
        BrowserUtils.waitFor(2);
        String ResponseJSON = getText(STUB_RESP_JSON);
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNode = objectMapper.readTree(ResponseJSON);
        JsonNode vcNode = jsonNode.get("vc");
        JsonNode evidenceNode = vcNode.get("evidence");
        JsonNode insideEvidence = evidenceNode.get(0);
        JsonNode activityHistoryScoreNode = insideEvidence.get("activityHistoryScore");
        String ActualactivityHistoryScore = activityHistoryScoreNode.asText();
        String ExpectedactivityHistoryScoreNode =
                userDetailsObject.getString("activityHistoryScore");
        Assert.assertEquals(ExpectedactivityHistoryScoreNode, ActualactivityHistoryScore);
        JsonNode checkDetailsNode = insideEvidence.get("checkDetails");
        JsonNode checkDetailsNodeone = checkDetailsNode.get(1);
        JsonNode checkMethodNode = checkDetailsNodeone.get("checkMethod");
        String ActualcheckMethod = checkMethodNode.asText();
        String ExpectedcheckMethod = userDetailsObject.getString("checkMethod");
        Assert.assertEquals(ExpectedcheckMethod, ActualcheckMethod);
        JsonNode checkBioVerNode = checkDetailsNodeone.get("biometricVerificationProcessLevel");
        String ActualbioVerScore = checkBioVerNode.asText();
        String ExpectedbioVerScore =
                userDetailsObject.getString("biometricVerificationProcessLevel");
        Assert.assertEquals(ExpectedbioVerScore, ActualbioVerScore);
        JsonNode validityNode = insideEvidence.get("validityScore");
        String ActualvalidityScore = validityNode.asText();
        String ExpectedvalidityScore = userDetailsObject.getString("validityScore");
        Assert.assertEquals(ExpectedvalidityScore, ActualvalidityScore);
        JsonNode strengthNode = insideEvidence.get("strengthScore");
        String ActualstrengthScore = strengthNode.asText();
        String ExpectedstrengthScore = userDetailsObject.getString("strengthScore");
        Assert.assertEquals(ExpectedstrengthScore, ActualstrengthScore);
    }

    public static void mobileStublivenessSuccess(String jsonResp) throws IOException {
        Assert.assertEquals("Continue to the service you want to use", getText(SUCCESS_HDR));
        clickElement(CONTINUE_BUTTON);
        BrowserUtils.waitForPageToLoad(20);
        JSONObject userDetailsObject =
                new JSONObject(
                        generateStringFromJsonPayloadResource(
                                USER_DATA_DIRECTORY, jsonResp.replaceAll(" ", "")));
        clickElement(VERIFY_CREDENTIALS);
        BrowserUtils.waitFor(2);
        String ResponseJSON = getText(STUB_RESP_JSON);
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNode = objectMapper.readTree(ResponseJSON);
        JsonNode vcNode = jsonNode.get("vc");
        JsonNode evidenceNode = vcNode.get("evidence");
        JsonNode insideEvidence = evidenceNode.get(0);
        JsonNode activityHistoryScoreNode = insideEvidence.get("activityHistoryScore");
        String ActualactivityHistoryScore = activityHistoryScoreNode.asText();
        String ExpectedactivityHistoryScoreNode =
                userDetailsObject.getString("activityHistoryScore");
        Assert.assertEquals(ExpectedactivityHistoryScoreNode, ActualactivityHistoryScore);
        JsonNode checkDetailsNode = insideEvidence.get("failedCheckDetails");
        JsonNode checkDetailsNodeone = checkDetailsNode.get(1);
        JsonNode checkMethodNode = checkDetailsNodeone.get("checkMethod");
        String ActualcheckMethod = checkMethodNode.asText();
        String ExpectedcheckMethod = userDetailsObject.getString("checkMethod");
        Assert.assertEquals(ExpectedcheckMethod, ActualcheckMethod);
        JsonNode checkBioVerNode = checkDetailsNodeone.get("biometricVerificationProcessLevel");
        String ActualbioVerScore = checkBioVerNode.asText();
        String ExpectedbioVerScore =
                userDetailsObject.getString("biometricVerificationProcessLevel");
        Assert.assertEquals(ExpectedbioVerScore, ActualbioVerScore);
        JsonNode validityNode = insideEvidence.get("validityScore");
        String ActualvalidityScore = validityNode.asText();
        String ExpectedvalidityScore = userDetailsObject.getString("validityScore");
        Assert.assertEquals(ExpectedvalidityScore, ActualvalidityScore);
        JsonNode strengthNode = insideEvidence.get("strengthScore");
        String ActualstrengthScore = strengthNode.asText();
        String ExpectedstrengthScore = userDetailsObject.getString("strengthScore");
        Assert.assertEquals(ExpectedstrengthScore, ActualstrengthScore);
    }

    public static void mobileAccessDeniedPassportSuccess(String jsonResp) throws IOException {
        Assert.assertEquals("YContinue to the service you want to use", getText(SUCCESS_HDR));
        clickElement(CONTINUE_BUTTON);
        BrowserUtils.waitForPageToLoad(20);
        JSONObject userDetailsObject =
                new JSONObject(
                        generateStringFromJsonPayloadResource(
                                USER_DATA_DIRECTORY, jsonResp.replaceAll(" ", "")));
        clickElement(VERIFY_CREDENTIAL4);
        BrowserUtils.waitFor(2);
        String ResponseJSON = getText(STUB_RESP_JSON4);
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNode = objectMapper.readTree(ResponseJSON);
        JsonNode vcNode = jsonNode.get("vc");
        JsonNode evidenceNode = vcNode.get("evidence");
        JsonNode insideEvidence = evidenceNode.get(0);
        JsonNode strengthScoreNode = insideEvidence.get("strengthScore");
        String ActualstrengthScore = strengthScoreNode.asText();
        String ExpectedstrengthScore = userDetailsObject.getString("strengthScore");
        Assert.assertEquals(ExpectedstrengthScore, ActualstrengthScore);
        JsonNode validityScoreNode = insideEvidence.get("validityScore");
        String ActualvalidityScore = validityScoreNode.asText();
        String ExpectedvalidityScore = userDetailsObject.getString("validityScore");
        Assert.assertEquals(ExpectedvalidityScore, ActualvalidityScore);
        JsonNode typeNode = insideEvidence.get("type");
        String Actualtype = typeNode.asText();
        String Expectedtype = userDetailsObject.getString("type");
        Assert.assertEquals(Expectedtype, Actualtype);
    }

    public void validateIpvCheckResults(String identityValidity) {
        Assert.assertEquals("Continue to the service you want to use", getText(SUCCESS_HDR));
    }

    public void checkPageUrl(String identityValidity) {
        String expectedResult = null;
        if (identityValidity.equals("Successfully")) {
            expectedResult = ConfigurationReader.get("dbs.success.url");
        } else if (identityValidity.equals("Unsuccessfully KBV")) {
            expectedResult = ConfigurationReader.get("dbs.no.success.kbv.url");
        } else if (identityValidity.equals("Unsuccessfully Address")) {
            expectedResult = ConfigurationReader.get("dbs.no.success.address.url");
        }
        Assert.assertEquals(
                "The URL returned was incorrect for a "
                        + identityValidity
                        + " check. Expected: "
                        + expectedResult
                        + " Actual: "
                        + getCurrentPageUrl(),
                expectedResult,
                getCurrentPageUrl());
    }

    public void checkPageTitle(String identityValidity) {
        String expectedResult;
        if (identityValidity.equals("Successfully")) {
            expectedResult = ConfigurationReader.get("dbs.success.title");
        } else {
            expectedResult = ConfigurationReader.get("dbs.no.success.title");
        }
        Assert.assertTrue(
                "The Page Title was returned incorrectly for a "
                        + identityValidity
                        + " check. Page Title expected to contain: "
                        + identityValidity,
                getText(PAGE_HEADER).contains(expectedResult));
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
