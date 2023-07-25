package uk.gov.di.ipv.cri.passport.acceptance_tests.step_definitions.stepDefsFromIpvRepo;

import io.cucumber.java.en.And;
import io.cucumber.java.en.Then;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo.CheckAndConfirmYourAddressPage;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo.ChooseYourAddressPage;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo.FindYourAddressPage;

import java.io.IOException;

public class AddressCriSteps {

    private final FindYourAddressPage findYourAddressPage = new FindYourAddressPage();
    private final ChooseYourAddressPage chooseYourAddressPage = new ChooseYourAddressPage();
    private final CheckAndConfirmYourAddressPage checkAndConfirmYourAddressPage =
            new CheckAndConfirmYourAddressPage();

    @Then("User should be on Address CRI Page")
    public void userShouldBeOnAddressCRIPage() {
        findYourAddressPage.waitForPageToLoad();
        findYourAddressPage.validateAddPage();
    }

    @And("the user {string} {string} adds their Address Details")
    public void theUserSuccessfullyAddsTheirAddressDetails(
            String userName, String addressCriSuccess) throws IOException {
        findYourAddressPage.searchForUserAddress(userName);
        chooseYourAddressPage.selectUserAddress(userName, addressCriSuccess);
        checkAndConfirmYourAddressPage.checkAndConfirmUserAddress(userName);
    }

    @And("user enters data in address stub and Click on submit data and generate auth code")
    public void userEntersDataInAddressStubAndClickOnSubmitDataAndGenerateAuthCode() {
        chooseYourAddressPage.selectStubUserAddress();
    }

    @Then("User should see error recovery page")
    public void userShouldSeeErrorRecoveryPage() {
        chooseYourAddressPage.backButtonErrPage();
    }
}
