package uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo;

import org.openqa.selenium.By;
import org.openqa.selenium.Keys;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.UtilitiesFromIpvRepo.PageObjectSupport;
import utilsFromIpvRepo.UiSupport;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Paths;

public class GlobalPage extends PageObjectSupport {
    WebDriver driver;

    public GlobalPage() {
        this.driver = getCurrentDriver();
    }

    static final By CONTINUE_BUTTON = By.xpath("//button[@class='govuk-button button']");

    public void clickContinue() {
        clickElement(CONTINUE_BUTTON);
    }

    public void waitForUrlToChange(String previousUrl, int waitMaxSeconds) {
        for (int i = 0; i <= waitMaxSeconds; i++) {
            if (!previousUrl.equals(getCurrentDriver().getCurrentUrl())) {
                return;
            }
            UiSupport.mySleep(1);
        }
    }

    public String getCurrentPageUrl() {
        return getCurrentDriver().getCurrentUrl();
    }

    public void populateDetailsInFields(By detailsSelector, String fieldValue) {
        waitForElementVisible(detailsSelector, 60);
        WebElement field = getCurrentDriver().findElement(detailsSelector);
        field.sendKeys(Keys.HOME, Keys.chord(Keys.SHIFT, Keys.END), fieldValue);
    }

    public void populateField(By selector, String value) {
        waitForElementVisible(selector, 60);
        WebElement field = getCurrentDriver().findElement(selector);
        field.sendKeys(value);
    }

    public static String generateStringFromJsonPayloadResource(
            String jsonResourcePath, String fileName) throws IOException {
        String jsonPayloadString = "";
        try {
            jsonPayloadString =
                    new String(Files.readAllBytes(Paths.get(jsonResourcePath + fileName + ".json")))
                            .replaceAll("\n", "");
            System.out.println("Json Payload Path is: " + jsonResourcePath + fileName + ".json");
        } catch (NoSuchFileException e) {
            jsonPayloadString =
                    new String(
                                    Files.readAllBytes(
                                            Paths.get(
                                                    jsonResourcePath
                                                            + "JSON/"
                                                            + fileName
                                                            + ".json")))
                            .replaceAll("\n", "");
            System.out.println(
                    "Json Payload Path is: " + jsonResourcePath + "JSON/" + fileName + ".json");
        }
        return jsonPayloadString;
    }

    public static Integer extractIntegerValueFromJsonString(String jsonString, String jsonPath) {
        return com.jayway.jsonpath.JsonPath.read(jsonString, jsonPath);
    }
}
