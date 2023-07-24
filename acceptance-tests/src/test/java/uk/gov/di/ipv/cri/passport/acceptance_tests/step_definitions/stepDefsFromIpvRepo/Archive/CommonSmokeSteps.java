package uk.gov.di.ipv.cri.passport.acceptance_tests.step_definitions.stepDefsFromIpvRepo.Archive;

import io.cucumber.java.en.When;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo.*;

public class CommonSmokeSteps {

    @When("I click continue")
    public void clickContinue() {
        new PassportPage().Continue.click();
    }
}
