package uk.gov.di.ipv.cri.passport.acceptance_tests.step_definitions.stepDefsFromIpvRepo.Archive;

import io.cucumber.java.en.And;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import org.junit.Assert;
import org.openqa.selenium.Cookie;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.OrchestratorStubPage;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo.Archive.AddressStubPage;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo.Archive.AnswerSecurityQuestionsPage;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo.Archive.EnterYourDetailsExactlyPage;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo.Archive.KnowledgeBasedVerificationStubPage;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo.FraudCheckStubPage;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo.YouHaveSignedInToYourGOVUKAccountPage;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo.YouHaveSuccessfullyProvedYourIdentityPage;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.Driver;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.UtilitiesFromIpvRepo.BrowserUtils;

public class FullJourneyRouteSteps {

    @When("I click on `Full journey route`")
    public void i_click_on_full_journey_route() {
        new OrchestratorStubPage().FullJourneyRoute.click();
        BrowserUtils.waitForPageToLoad(10);
    }

    @Then("I should be on `You’ve signed in to your GOV.UK One Login` page")
    public void i_should_be_on_you_ve_signed_in_to_your_gov_uk_one_login_page() {
        String currentPageTitle = Driver.get().getTitle();
        String expectedPageTitle = "Prove your identity - GDS";
        System.out.println("currentPageTitle = " + currentPageTitle);
        System.out.println("expectedPageTitle = " + expectedPageTitle);
        Assert.assertEquals(expectedPageTitle, currentPageTitle);
    }

    @When("I click `Continue`")
    public void i_click_continue() {
        new YouHaveSignedInToYourGOVUKAccountPage().Continue.click();
        BrowserUtils.waitForPageToLoad(10);
    }

    @When("I enter Kenneth Decerqueira's details and click Continue")
    public void i_enter_kenneth_decerqueira_s_details_and_click_continue() {
        new EnterYourDetailsExactlyPage().PassportNumber.sendKeys("321654987");
        new EnterYourDetailsExactlyPage().Surname.sendKeys("Decerqueira");
        new EnterYourDetailsExactlyPage().Firstname.sendKeys("Kenneth");
        new EnterYourDetailsExactlyPage().DayOfBirth.sendKeys("08");
        new EnterYourDetailsExactlyPage().MonthOfBirth.sendKeys("07");
        new EnterYourDetailsExactlyPage().YearOfBirth.sendKeys("1965");

        new EnterYourDetailsExactlyPage().PassportExpiryDay.sendKeys("01");
        new EnterYourDetailsExactlyPage().PassportExpiryMonth.sendKeys("10");
        new EnterYourDetailsExactlyPage().PassportExpiryYear.sendKeys("2042");

        new EnterYourDetailsExactlyPage().Continue.click();
    }

    @Then("I should be on UK Passport \\(Stub)")
    public void i_should_be_on_uk_passport_stub() {
        // Write code here that turns the phrase above into concrete actions
        throw new io.cucumber.java.PendingException();
    }

    @When(
            "I supply data in JSON format, GPG Strength {int}, Validity {int} and click `Submit data and generate auth code`")
    public void
            i_supply_data_in_json_format_gpg_strength_validity_and_click_submit_data_and_generate_auth_code(
                    Integer int1, Integer int2) {
        // Write code here that turns the phrase above into concrete actions
        throw new io.cucumber.java.PendingException();
    }

    @Then("I should be on Address \\(Stub)")
    public void i_should_be_on_address_stub() {
        Assert.assertTrue(new AddressStubPage().JSONPayLoader.isDisplayed());
    }

    @When("I supply data in JSON format and click `Submit data and generate auth code`")
    public void i_supply_data_in_json_format_and_click_submit_data_and_generate_auth_code() {
        new AddressStubPage().JSONPayLoader.sendKeys("{ \"test\" : \"example\" }");
        new AddressStubPage().SubmitDataAndGenerateAuthCode.click();
        BrowserUtils.waitForPageToLoad(10);
    }

    @Then("I should be on Fraud Check \\(Stub)")
    public void i_should_be_on_fraud_check_stub() {
        Assert.assertTrue(new FraudCheckStubPage().JSONPayLoader.isDisplayed());
    }

    @When(
            "I supply data in JSON format, Fraud value {int} and click on `Submit data and generate auth code`")
    public void
            i_supply_data_in_json_format_fraud_value_and_click_on_submit_data_and_generate_auth_code(
                    Integer int1) {
        new FraudCheckStubPage().JSONPayLoader.sendKeys("{ \"test\" : \"example\" }");
        new FraudCheckStubPage().FraudValue.sendKeys("1");
        new FraudCheckStubPage().SubmitDataAndGenerateAuthCode.click();
    }

    @Then("I should be on `Answer security questions` page")
    public void i_should_be_on_answer_security_questions_page() {
        Assert.assertTrue(new AnswerSecurityQuestionsPage().Start.isDisplayed());
    }

    @When("I click `Start`")
    public void i_click_start() {
        new AnswerSecurityQuestionsPage().Start.click();
        BrowserUtils.waitForPageToLoad(10);
    }

    @Then("I should be on Knowledge Based Verification \\(Stub)")
    public void i_should_be_on_knowledge_based_verification_stub() {
        Assert.assertTrue(new KnowledgeBasedVerificationStubPage().JSONPayLoader.isDisplayed());
    }

    @When(
            "I supply data in JSON format, Verification value {int} and click on `Submit data and generate auth code`")
    public void
            i_supply_data_in_json_format_verification_value_and_click_on_submit_data_and_generate_auth_code(
                    Integer int1) {
        new KnowledgeBasedVerificationStubPage()
                .JSONPayLoader.sendKeys("{ \"test\" : \"example\" }");
        new KnowledgeBasedVerificationStubPage().Verification.sendKeys("1");
        new KnowledgeBasedVerificationStubPage().SubmitDataAndGenerateAuthCode.click();
    }

    @Then("I should be on You've successfully proved your identity page")
    public void i_should_be_on_you_ve_successfully_proved_your_identity_page() {
        Assert.assertTrue(new YouHaveSuccessfullyProvedYourIdentityPage().Continue.isDisplayed());
    }

    @And("when I updated cookies can see the stub content in Welsh")
    public void whenIUpdatedCookiesCanSeeTheStubContentInWelsh() {
        Cookie cookie = new Cookie("lng", "cy");
        Driver.get().manage().addCookie(cookie);
    }

    @And("I delete the cookies for language")
    public void iDeleteTheCookiesForLanguage() {
        Cookie cookie = new Cookie("lng", "cy");
        Driver.get().manage().deleteCookie(cookie);
        Driver.get().navigate().refresh();
        BrowserUtils.waitFor(2);
    }
}
