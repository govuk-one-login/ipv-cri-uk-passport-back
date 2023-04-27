package uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.UtilitiesFromIpvRepo;

import com.jayway.jsonpath.JsonPath;
import org.json.simple.JSONObject;
import org.openqa.selenium.By;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.Keys;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.TimeoutException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.Driver;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.fail;

public class PageObjectSupport {

    protected void populateField(By element, String value) {
        getCurrentDriver().findElement(element).click();
        getCurrentDriver().findElement(element).clear();
        getCurrentDriver().findElement(element).sendKeys(value);
        getCurrentDriver().findElement(element).sendKeys(Keys.TAB.toString());
    }

    public static void clickElement(By element) {
        getCurrentDriver().findElement(element).click();
    }

    public static String getText(By element) {
        return getCurrentDriver().findElement(element).getText();
    }

    protected WebElement waitForElementVisible(By by) {
        return waitForElementVisible(by, 5);
    }

    protected WebElement waitForElementVisible(By by, int seconds) {
        try {
            WebDriverWait wait = new WebDriverWait(getCurrentDriver(), Duration.ofSeconds(seconds));
            wait.until(ExpectedConditions.visibilityOfElementLocated(by));
        } catch (NoSuchElementException | TimeoutException e) {
            fail("Element is not visible " + by.toString());
            fail(
                    "Element  "
                            + by.toString()
                            + " is not visible on the page "
                            + getCurrentDriver().getPageSource());
        }
        return getCurrentDriver().findElement(by);
    }

    protected boolean isElementPresent(By by) {
        WebDriverWait wait = new WebDriverWait(getCurrentDriver(), Duration.ofSeconds(10));
        try {
            wait.until(ExpectedConditions.visibilityOfElementLocated(by));
            getCurrentDriver().findElement(by);
            return true;
        } catch (NoSuchElementException | TimeoutException e) {
            return false;
        }
    }

    protected void waitForElementNotVisible(By by, int seconds) {
        WebDriverWait wait = new WebDriverWait(getCurrentDriver(), Duration.ofSeconds(seconds));
        wait.until(ExpectedConditions.numberOfElementsToBeLessThan(by, 1));
    }

    protected void waitForElementNotVisible(By by) throws InterruptedException {
        if (isElementPresent(by)) waitForElementNotVisible(by, 60);
        else waitForPageToLoad();
    }

    protected WebElement waitForElementClickable(By by) {
        return waitForElementClickable(by, 30);
    }

    protected WebElement waitForElementClickable(By by, int seconds) {
        try {
            WebDriverWait wait = new WebDriverWait(getCurrentDriver(), Duration.ofSeconds(seconds));
            wait.until(ExpectedConditions.elementToBeClickable(by));
        } catch (NoSuchElementException | TimeoutException e) {
            fail("Element is not visible " + by.toString());
        }
        return getCurrentDriver().findElement(by);
    }

    /**
     * Waits up to 1 minute for the page to load. This method should be updated as was created in
     * 2017 and catch block logis is useless
     */
    public void waitForPageToLoad() throws InterruptedException {
        try {
            WebDriverWait wait = new WebDriverWait(getCurrentDriver(), Duration.ofSeconds(60));
            wait.until(
                    drv ->
                            ((JavascriptExecutor) getCurrentDriver())
                                    .executeScript("return document.readyState")
                                    .toString()
                                    .equals("complete"));
        } catch (TimeoutException e) {
            // Swallow this and continue
            // FIXME: Should raise an error when the page can not be loaded as it is confusing to
            // have a separate later test fail!
            // FIXME: Write to logger not standard out! (why this way?)
            new RuntimeException("Wait for page to load returned Timeout exception");
        }
    }

    public String getAttribute(JSONObject json, String path) {
        return JsonPath.read(json.toString(), path);
    }

    public static WebDriver getCurrentDriver() {
        return Driver.get();
    }

    public void clearText(By element) {
        getCurrentDriver().findElement(element).clear();
    }
}
