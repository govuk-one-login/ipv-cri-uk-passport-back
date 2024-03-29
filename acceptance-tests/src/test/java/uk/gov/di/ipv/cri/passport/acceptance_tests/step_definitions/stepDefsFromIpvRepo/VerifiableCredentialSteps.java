package uk.gov.di.ipv.cri.passport.acceptance_tests.step_definitions.stepDefsFromIpvRepo;

import io.cucumber.java.en.Then;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo.IpvCheckResultsPage;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo.UserInfomationPage;

public class VerifiableCredentialSteps {

    private final IpvCheckResultsPage ipvCheckResultsPage = new IpvCheckResultsPage();
    private final UserInfomationPage userInfomationPage = new UserInfomationPage();

    @Then(
            "the user should see that they have {string} proved their identity using the Orchestrator Stub")
    public void theUserShouldSeeThatTheyHaveProvedTheirIdentityOrchestratorStub(
            String identityValidity) {
        ipvCheckResultsPage.validateIpvCheckResults(identityValidity);
        ipvCheckResultsPage.clickContinue();
        userInfomationPage.validateUserInformationTitle();
    }

    @Then("the user should be taken to the IPV Reuse Screen with One login changes")
    public void theUserShouldBeTakenToTheIPVReuseScreenWithOneLoginChanges() {
        ipvCheckResultsPage.validateRebranding();
    }
}
