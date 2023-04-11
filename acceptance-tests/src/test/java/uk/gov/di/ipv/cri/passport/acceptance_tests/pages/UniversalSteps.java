package uk.gov.di.ipv.cri.passport.acceptance_tests.pages;

import org.openqa.selenium.support.PageFactory;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.Driver;

import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class UniversalSteps {

    public UniversalSteps() {
        PageFactory.initElements(Driver.get(), this);
    }

    public void waitForTextToAppear(String text) {
        String header = Driver.get().getTitle();
        Driver.get().manage().timeouts().implicitlyWait(10, TimeUnit.SECONDS);

        if (header.contains(text)) {
            assertTrue(Driver.get().getTitle().contains(text));
        } else {
            fail("Page Title Does Not Match " + text + "But was " + Driver.get().getTitle());
        }
    }

    public void driverClose() {
        Driver.closeDriver();
    }

    public void assertURLContains(String expected) {
        String url = Driver.get().getCurrentUrl();
        assertTrue(url.contains(expected));
    }
}
