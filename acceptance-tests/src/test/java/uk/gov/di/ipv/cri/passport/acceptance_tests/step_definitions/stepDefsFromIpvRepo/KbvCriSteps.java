package uk.gov.di.ipv.cri.passport.acceptance_tests.step_definitions.stepDefsFromIpvRepo;

import io.cucumber.java.en.And;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import org.junit.Assert;
import org.openqa.selenium.By;
import org.openqa.selenium.support.ui.Select;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo.*;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.Driver;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.UtilitiesFromIpvRepo.BrowserUtils;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.UtilitiesFromIpvRepo.ConfigurationReader;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.fail;
import static uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.UtilitiesFromIpvRepo.PageObjectSupport.clickElement;

public class KbvCriSteps {
    private final KbvQuestionPage kbvQuestionPage = new KbvQuestionPage();
    private final AnswerSecurityQuestionPage answerSecurityQuestionPage =
            new AnswerSecurityQuestionPage();
    private final String SUCCESSFULLY = "Successfully";
    private final String UNSUCCESSFULLY = "Unsuccessfully";
    private static final By JWT_CHECK_BOX = By.cssSelector("#vcExpiryFlg");
    private static final By CONTINUE_BUTTON = By.xpath("//button[@name='submitButton']");

    @And("the user {string} {string} passes the KBV CRI Check")
    public void theUserSuccessfullyPassesKBVCRICheck(String userName, String kbvQuestionSuccess)
            throws IOException {
        answerSecurityQuestionPage.clickContinue();
        if (kbvQuestionSuccess.equals(SUCCESSFULLY)) {
            int SUCCESSFUL_KBV_QUESTION_COUNT = 3;
            for (int i = 0; i < SUCCESSFUL_KBV_QUESTION_COUNT; i++) {
                kbvQuestionPage.answerKbvQuestion(kbvQuestionSuccess, userName);
            }
        } else if (kbvQuestionSuccess.equals(UNSUCCESSFULLY)) {
            int UNSUCCESSFUL_KBV_QUESTION_COUNT = 2;
            for (int i = 0; i < UNSUCCESSFUL_KBV_QUESTION_COUNT; i++) {
                kbvQuestionPage.answerKbvQuestion(kbvQuestionSuccess, userName);
            }
        } else {
            fail(
                    "Valid KBV Option not selected in BDD Statement. Possible Values: Successfully, Unsuccessfully");
        }
    }

    @Then("User should be on KBV page and click continue")
    public void userShouldBeOnKBVPageAndClickContinue() {
        BrowserUtils.waitForPageToLoad(10);
        Assert.assertEquals(
                "Answer security questions", new IpvCoreFrontPageArchive().Kbvheader.getText());
        new PassportPage().Continue.click();
    }

    @When("user enters data in kbv stub and Click on submit data and generate auth code")
    public void userEntersDataInKbvStubAndClickOnSubmitDataAndGenerateAuthCode() {
        Select select = new Select(new IpvCoreFrontPageArchive().SelectkbvCRIData);
        select.selectByValue("Kenneth Decerqueira (Valid Experian) KBV");
        new IpvCoreFrontPageArchive().kbvscore.sendKeys("2");
        new PassportPage().SelectCRIData.click();
        clickElement(JWT_CHECK_BOX);
        new IpvCoreFrontPageArchive().JWT_EXP_HR.clear();
        new IpvCoreFrontPageArchive().JWT_EXP_HR.sendKeys("4");
        BrowserUtils.waitForPageToLoad(10);
        new PassportPage().submitdatagenerateauth.click();
    }

    @Then("user should be successful in proving identity")
    public void userShouldBeSuccessfulInProvingIdentity() {
        Assert.assertEquals(
                "Continue to the service you want to use",
                new IpvCoreFrontPageArchive().journeycomplete.getText());
    }

    @Then("user should be successful in proving identity in Welsh")
    public void userShouldBeSuccessfulInProvingIdentityInWelsh() {
        Assert.assertEquals(
                "Parhau i’r gwasanaeth rydych am ei ddefnyddio",
                new IpvCoreFrontPageArchive().journeycomplete.getText());
    }

    @Then("User should be on KBV page")
    public void userShouldBeOnKBVPage() {
        BrowserUtils.waitForPageToLoad(10);
        Assert.assertEquals(
                "Answer security questions", new IpvCoreFrontPageArchive().Kbvheader.getText());
    }

    @And("User should be able to see the json response page")
    public void userShouldBeAbleToSeeTheJsonResponsePage() {
        clickElement(CONTINUE_BUTTON);
        Assert.assertEquals(
                "Raw User Info Object", new IpvCoreFrontPageArchive().RAW_JSON.getText());
    }

    @When(
            "user enters data in kbv stub for KBV Thin and Click on submit data and generate auth code")
    public void userEntersDataInKbvStubForKBVThinAndClickOnSubmitDataAndGenerateAuthCode() {
        Select select = new Select(new IpvCoreFrontPageArchive().SelectkbvCRIData);
        select.selectByValue("Kenneth Decerqueira (Valid Experian) KBV");
        new IpvCoreFrontPageArchive().kbvscore.sendKeys("0");
        new PassportPage().SelectCRIData.click();
        BrowserUtils.waitForPageToLoad(10);
        new PassportPage().submitdatagenerateauth.click();
    }

    @Then("KBV Thin Error Page should be displayed")
    public void kbvThinErrorPageShouldBeDisplayed() {
        Assert.assertEquals(
                "You need to prove your identity another way",
                new IpvCoreFrontPageArchive().Kbvheader.getText());
    }

    @When(
            "user enters data in kbv stub for KBV fail and Click on submit data and generate auth code")
    public void userEntersDataInKbvStubForKBVFailAndClickOnSubmitDataAndGenerateAuthCode() {
        Select select = new Select(new IpvCoreFrontPageArchive().SelectkbvCRIData);
        select.selectByValue("Kenneth Decerqueira (Valid Experian) KBV");
        new IpvCoreFrontPageArchive().kbvscore.sendKeys("2");
        new PassportPage().SelectCRIData.click();
        new IpvCoreFrontPageArchive().updateci.sendKeys("D02");
        BrowserUtils.waitForPageToLoad(10);
        new PassportPage().submitdatagenerateauth.click();
    }

    @Then("KBV fail Error Page should be displayed")
    public void kbvFailErrorPageShouldBeDisplayed() {
        Assert.assertEquals(
                "Sorry, we cannot prove your identity",
                new IpvCoreFrontPageArchive().Kbvheader.getText());
    }
}
