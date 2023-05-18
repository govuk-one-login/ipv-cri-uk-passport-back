package uk.gov.di.ipv.cri.passport.acceptance_tests.step_definitions.stepDefsFromIpvRepo.Archive;

import io.cucumber.java.en.And;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import org.junit.Assert;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo.*;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo.Archive.CheckYourDetails;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo.Archive.DiIpvCoreFrontPage;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo.IpvCoreFrontPageArchive;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.UtilitiesFromIpvRepo.BrowserUtils;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class CommonSmokeSteps {
    public static final String CORE_FRONT_DEBUG_H1 = "di-ipv-core-front";
    String KennethPostcode = "BA2 5AA";

    @Then("I should get five options")
    public void i_should_get_five_options() {
        Assert.assertTrue(new IpvCoreFrontPageArchive().UkPassport.isDisplayed());
    }

    //    @Then("I should be on `What's your current home address?` page")
    //    public void i_should_be_on_what_s_your_current_home_address_page() {
    //        Assert.assertTrue(new
    // WhatsYourCurrentHomeAddressPage().FindAddressButton.isDisplayed());
    //        BrowserUtils.waitForPageToLoad(10);
    //    }
    //
    //    @When("I enter postcode and click `Find address`")
    //    public void i_enter_postcode_and_click_find_address() {
    //        new WhatsYourCurrentHomeAddressPage().Postcode.sendKeys(KennethPostcode);
    //        new WhatsYourCurrentHomeAddressPage().FindAddressButton.click();
    //        BrowserUtils.waitForPageToLoad(10);
    //    }
    //
    //    @When("I choose address from dropdown and click `Select address`")
    //    public void i_choose_address_from_dropdown_and_click_select_address() {
    //        Select select = new Select(new WhatsYourCurrentHomeAddressPage().SelectAnAddress);
    //        select.selectByValue("8 HADLEY ROAD, BATH, BA2 5AA");
    //        new WhatsYourCurrentHomeAddressPage().SelectAddress.click();
    //        BrowserUtils.waitForPageToLoad(10);
    //    }
    //
    //    @When("I enter `Year` and click `Continue`")
    //    public void i_enter_year_and_click_continue() {
    //        new WhatsYourCurrentHomeAddressPage().Year.sendKeys("2020");
    //        new WhatsYourCurrentHomeAddressPage().Continue.click();
    //        BrowserUtils.waitForPageToLoad(10);
    //    }

    @Then("I should be on `Check your details` page")
    public void i_should_be_on_check_your_details_page() {
        Assert.assertTrue(new CheckYourDetails().Continue.isDisplayed());
        BrowserUtils.waitForPageToLoad(10);
    }

    @When("I click `Continue` button on `Check your details` page")
    public void i_click_continue_button_on_check_your_details_page() {
        new CheckYourDetails().Continue.click();
        BrowserUtils.waitForPageToLoad(10);
    }

    @Then("I should be on `di-ipv-core-front` page")
    public void i_should_be_on_di_ipv_core_front_page() {
        Assert.assertTrue(new DiIpvCoreFrontPage().AuthorizeAndReturn.isDisplayed());
    }

    @When("I click continue")
    public void clickContinue() {
        new PassportPage().Continue.click();
    }

    @When("I should be on the core front debug page")
    public void checkH1() {
        assertEquals(CORE_FRONT_DEBUG_H1, new IpvCoreFrontPageArchive().h1.getText());
    }

    @Then("I should see GPG45 Score displayed")
    public void i_should_see_gpg45_score_displayed() {
        Assert.assertTrue(new IpvCoreFrontPageArchive().CredentialAttributes.isDisplayed());
    }

    @When("I click on Authorize and Return")
    public void i_click_on_authorize_and_return() {
        new IpvCoreFrontPageArchive().AuthorizeAndReturn.click();
        BrowserUtils.waitForPageToLoad(10);
    }

    @Then("I should see User information displayed")
    public void i_should_see_user_information_displayed() {
        Assert.assertTrue(new UserInformationPage().VerifiableCredential.isDisplayed());
    }

    @When("I click on Verifiable Credentials")
    public void i_click_on_verifiable_credentials() {
        new UserInformationPage().VerifiableCredential.click();
        BrowserUtils.waitForPageToLoad(10);
    }

    @Given("I should see validity score {} in the JSON payload")
    public void i_should_see_validity_data_in_json_payload(String validityScore) {
        String payload = new DiIpvCoreFrontPage().VerifiableCredentialJSONPayload.getText();
        System.out.println("payload = " + payload);
        Boolean visibilityOfvalidityScore = payload.contains(validityScore);
        System.out.println("visibilityOfvalidityScore = " + visibilityOfvalidityScore);
        Assert.assertTrue(visibilityOfvalidityScore);
    }

    @Given("I should see JSON payload displayed")
    public void i_should_see_my_name_in_json_payload() {
        Assert.assertTrue(new DiIpvCoreFrontPage().Verifiablejson.isDisplayed());
    }

    @When("I click on ukPassport\\(Stub)")
    public void iClickOnUkPassportStub() {
        new IpvCoreFrontPageArchive().UkPassport.click();
        BrowserUtils.waitForPageToLoad(10);
    }

    @And("I should see Strength score {} in the JSON payload")
    public void iShouldSeeStrengthScoreInTheJSONPayload(String strengthScore) {
        String payload = new DiIpvCoreFrontPage().VerifiableCredentialJSONPayload.getText();
        System.out.println("payload = " + payload);
        Boolean visibilityOfstrenghtScore = payload.contains(strengthScore);
        System.out.println("visibilityOfstrenghtScore = " + visibilityOfstrenghtScore);
        Assert.assertTrue(visibilityOfstrenghtScore);
    }

    @And("the user clicks on Continue")
    public void theUserClicksOnContinue() {
        new YouHaveSignedInToYourGOVUKAccountPage().Continue.click();
        BrowserUtils.waitForPageToLoad(10);
    }

    @Then("user should be on Address Stub")
    public void userShouldBeOnAddressStub() {
        BrowserUtils.waitForPageToLoad(10);
        Assert.assertEquals("Address (Stub)", new IpvCoreFrontPageArchive().Addresssstub.getText());
    }

    //    @When("user enters data in address stub and Click on submit data and generate auth code")
    //    public void userEntersDataInAddressStubAndClickOnSubmitDataAndGenerateAuthCode() {
    //
    ////        Select select = new Select(new IpvCoreFrontPage().SelectaddCRIData);
    ////        select.selectByValue("Kenneth Decerqueira (Valid Experian) Address");
    ////        new PassportPage().SelectCRIData.click();
    ////        BrowserUtils.waitForPageToLoad(10);
    ////        new PassportPage().Authorization.click();
    ////        new PassportPage().submitdatagenerateauth.click();
    //    }

    //    @Then("user should be on Fraud Check \\(Stub)")
    //    public void userShouldBeOnFraudCheckStub() {
    //        BrowserUtils.waitForPageToLoad(10);
    //        Assert.assertEquals("Fraud Check (Stub)",new IpvCoreFrontPage().FraudStub.getText());
    //    }

    //    @When("user enters data in fraud stub and Click on submit data and generate auth code")
    //    public void userEntersDataInFraudStubAndClickOnSubmitDataAndGenerateAuthCode() {
    //        Select select = new Select(new IpvCoreFrontPage().SelectfraudCRIData);
    //        select.selectByValue("Kenneth Decerqueira (Valid Experian) Fraud");
    //        new IpvCoreFrontPage().fraudscore.sendKeys("2");
    //        new IpvCoreFrontPage().contraIndicators.sendKeys("A01");
    //        new PassportPage().SelectCRIData.click();
    //        BrowserUtils.waitForPageToLoad(10);
    //        new PassportPage().submitdatagenerateauth.click();
    //    }

    //    @Then("User should be on KBV page and click continue")
    //    public void userShouldBeOnKBVPageAndClickContinue() {
    //        BrowserUtils.waitForPageToLoad(10);
    //        Assert.assertEquals("Answer security questions",new
    // IpvCoreFrontPage().Kbvheader.getText());
    //        new PassportPage().Continue.click();
    //    }

    //    @When("user enters data in kbv stub and Click on submit data and generate auth code")
    //    public void userEntersDataInKbvStubAndClickOnSubmitDataAndGenerateAuthCode() {
    //        Select select = new Select(new IpvCoreFrontPage().SelectkbvCRIData);
    //        select.selectByValue("Kenneth Decerqueira (Valid Experian) KBV");
    //        new IpvCoreFrontPage().kbvscore.sendKeys("2");
    //        new PassportPage().SelectCRIData.click();
    //        BrowserUtils.waitForPageToLoad(10);
    //        new PassportPage().submitdatagenerateauth.click();
    //    }

    //    @Then("user should be successful in proving identity")
    //    public void userShouldBeSuccessfulInProvingIdentity() {
    //        Assert.assertEquals("You’ve successfully proved your identity",new
    // IpvCoreFrontPage().journeycomplete.getText());
    //    }

    @Then("I should see validity score {string} and the Strength score {string} in JSON payload")
    public void iShouldSeeValidityScoreAndTheStrengthScoreInJSONPayload(
            String validityScore, String strengthScore) {
        String payload = new DiIpvCoreFrontPage().VerifiableCredentialJSONPayload.getText();
        boolean visibilityOfValidityScore = payload.contains(validityScore);
        Assert.assertTrue(visibilityOfValidityScore);
        boolean visibilityOfStrengthScore = payload.contains(strengthScore);
        Assert.assertTrue(visibilityOfStrengthScore);
    }

    //    @And("I Select app user journey")
    //    public void iSelectAppUserJourney() {
    //        Select select = new Select(new MobileAppStubPage().SelectAppJourney);
    //        Optional<WebElement> appJourneyUserOption = select
    //                .getOptions()
    //                .stream()
    //                .filter(option -> option.getText().contains("App journey user"))
    //                .findFirst();
    //        if (!appJourneyUserOption.isPresent()) {
    //            throw new NoSuchElementException("Cannot locate option containing text: " + "App
    // journey user");
    //        }
    //        select.selectByVisibleText(appJourneyUserOption.get().getText());
    //        new MobileAppStubPage().SelectAppJourney.click();
    //        BrowserUtils.waitForPageToLoad(10);
    //    }
}
