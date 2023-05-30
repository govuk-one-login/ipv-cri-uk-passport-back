package uk.gov.di.ipv.cri.passport.acceptance_tests.step_definitions;

import io.cucumber.java.en.Given;
import io.cucumber.java.en.When;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.OrchestratorStubPage;
import uk.gov.di.ipv.cri.passport.acceptance_tests.service.ConfigurationService;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.BrowserUtils;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.Driver;

public class CommonSteps {

    private final ConfigurationService configurationService =
            new ConfigurationService(System.getenv("ENVIRONMENT"));

    @Given("I am on Orchestrator Stub")
    public void i_am_on_orchestrator_stub() {
        Driver.get().get(configurationService.getOrchestratorStubUrl());
        BrowserUtils.waitForPageToLoad(10);
    }

    @When("I click on Full journey route")
    public void i_click_on_full_journey_route() {
        new OrchestratorStubPage().FullJourneyRoute.click();
        BrowserUtils.waitForPageToLoad(10);
    }

    @When("I click on Debug route")
    public void i_click_on_debug_route() {
        new OrchestratorStubPage().DebugRoute.click();
        BrowserUtils.waitForPageToLoad(10);
    }
}
