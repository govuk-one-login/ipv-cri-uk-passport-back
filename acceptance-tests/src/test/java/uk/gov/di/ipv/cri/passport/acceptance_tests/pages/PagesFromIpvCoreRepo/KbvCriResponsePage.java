package uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo;

import org.openqa.selenium.By;

public class KbvCriResponsePage extends GlobalPage {

    private static final By KBV_RESPONSE_LINK = By.cssSelector(".govuk-details__summary-text");
    private static final By KBV_RESPONSE_DATA = By.cssSelector("#data");
    public static final String VERIFICATION_SCORE = "Verification Score";
    public static final String VERIFICATION_SCORE_PATH = "$.vc.evidence[0].verificationScore";

    public void clickKbvResponseLink() {
        clickElement(KBV_RESPONSE_LINK);
    }

    public Object getKbvCriAttribute(String attribute) {
        String kbvResponseData = getText(KBV_RESPONSE_DATA);
        Object attributeValue = "";
        if (attribute.equals(VERIFICATION_SCORE)) {
            attributeValue =
                    extractIntegerValueFromJsonString(kbvResponseData, VERIFICATION_SCORE_PATH);
        }
        return attributeValue;
    }
}
