package uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo;

import org.json.JSONObject;
import org.openqa.selenium.By;
import org.openqa.selenium.NoSuchElementException;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.fail;

public class KbvQuestionPage extends GlobalPage {

    private static final By QUESTION_FIELD_SET = By.cssSelector(".govuk-fieldset");
    private static final By FIRST_ANSWER_RADIO_BUTTON =
            By.cssSelector(".govuk-radios__item:nth-child(1)");
    private static final By NONE_OF_THE_ABOVE =
            By.xpath("//input[contains(@id,'NONEOFTHEABOVEDOESNOTAPPLY')]");
    private static final By CONTINUE = By.cssSelector("#continue");
    private static final String USER_DATA_DIRECTORY = "src/test/resources/data/";

    public static final String FIELD_SET_SUFFIX = "-fieldset";
    public static final String ID = "id";
    public static final String COMMA_REGEX = "\\s*,\\s*";

    public void answerKbvQuestion(String answerType, String username) throws IOException {
        waitForElementVisible(QUESTION_FIELD_SET);
        String questionID =
                getCurrentDriver()
                        .findElement(QUESTION_FIELD_SET)
                        .getAttribute(ID)
                        .split(FIELD_SET_SUFFIX)[0];
        JSONObject userDetailsObject =
                new JSONObject(
                        generateStringFromJsonPayloadResource(USER_DATA_DIRECTORY, username));
        String[] userAnswerIds = userDetailsObject.getString(questionID).split(COMMA_REGEX);
        boolean answerOnPage = true;
        try {
            for (String answerId : userAnswerIds) {
                By answerSelector = By.id(answerId);
                if (isElementPresent(answerSelector)) {
                    answerOnPage = true;
                    if (answerType.equals("Successfully")) {
                        clickElement(answerSelector);
                    } else {
                        clickElement(NONE_OF_THE_ABOVE);
                    }
                    clickElement(CONTINUE);
                    break;
                } else {
                    answerOnPage = false;
                }
            }
            if (!answerOnPage) {
                if (answerType.equals("Successfully")) {
                    clickElement(NONE_OF_THE_ABOVE);
                    clickElement(CONTINUE);
                } else {
                    clickElement(FIRST_ANSWER_RADIO_BUTTON);
                    clickElement(CONTINUE);
                }
            }
        } catch (NoSuchElementException e) {
            fail(
                    "No "
                            + answerType
                            + " KBV answers were found for questionID "
                            + questionID
                            + ". Error: "
                            + e);
        }
    }
}
