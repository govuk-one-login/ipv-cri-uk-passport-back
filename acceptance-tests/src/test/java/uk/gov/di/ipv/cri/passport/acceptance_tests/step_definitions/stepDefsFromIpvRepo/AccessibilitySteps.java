package uk.gov.di.ipv.cri.passport.acceptance_tests.step_definitions.stepDefsFromIpvRepo;

import com.deque.axe.AXE;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Assert;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.Driver;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.UtilitiesFromIpvRepo.BrowserUtils;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.UtilitiesFromIpvRepo.ConfigurationReader;

import java.io.IOException;
import java.net.URL;

public class AccessibilitySteps {

    int numberOfSeriousAndSevereIssues;

    private static final URL scriptUrl = AccessibilitySteps.class.getResource("/axe.min.js");

    @Given("I am on the test page")
    public void i_am_on_the_test_page() {
        Driver.get().get(ConfigurationReader.get("addressConfirmPage"));
        BrowserUtils.waitForPageToLoad(10);
    }

    @When("I run AXE Accessibility Test")
    public void i_run_axe_accessibility_test() throws IOException {
        System.out.println("Page in test = " + Driver.get().getTitle());
        JSONObject responseJSON = new AXE.Builder(Driver.get(), scriptUrl).analyze();
        System.out.println("responseJSON.toString() = " + responseJSON.toString());

        JSONArray violations = responseJSON.getJSONArray("violations");

        System.out.println("Number of violations = " + violations.length());

        numberOfSeriousAndSevereIssues = 0;
        for (int i = 0; i < violations.length(); i++) {
            JSONObject violation = violations.getJSONObject(i);
            if (violation.get("impact").equals("serious")
                    || violation.get("impact").equals("severe")
                    || violation.get("impact").equals("critical")) {
                numberOfSeriousAndSevereIssues = numberOfSeriousAndSevereIssues + 1;
            }
            System.out.println("Violation " + (i + 1) + " = " + violation.get("help"));
            System.out.println("Violation " + (i + 1) + " impact = " + violation.get("impact"));
            System.out.println(
                    "numberOfSeriousAndSevereIssues = " + numberOfSeriousAndSevereIssues);
        }
    }

    @Then("the number of `Critical` or `Severe` or `Serious` issues detected must be zero")
    public void the_number_of_Critical_or_Severe_or_Serious_issues_detected_must_be_zero() {
        Assert.assertEquals(0, numberOfSeriousAndSevereIssues);
    }

    @Given("I am on the {string}")
    public void i_am_on_the(String testPage) {
        Driver.get().get(ConfigurationReader.get(testPage));
        // BrowserUtils.waitForPageToLoad(10);
        BrowserUtils.waitFor(3);
    }
}
