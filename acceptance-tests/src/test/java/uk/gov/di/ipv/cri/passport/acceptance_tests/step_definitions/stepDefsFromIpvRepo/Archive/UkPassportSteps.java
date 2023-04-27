package uk.gov.di.ipv.cri.passport.acceptance_tests.step_definitions.stepDefsFromIpvRepo.Archive;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.cucumber.java.en.Then;
import org.junit.Assert;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo.IpvCoreFrontPageArchive;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PagesFromIpvCoreRepo.UserInformationPage;

public class UkPassportSteps {

    @Then("GPG45 Score for Strength must be {int} and Validity must be {int}")
    public void gpg45_score_for_strength_must_be_and_validity_must_be(Integer int1, Integer int2)
            throws JsonProcessingException {
        String GPG45Score = new IpvCoreFrontPageArchive().GPG45Score.getText();
        System.out.println("GPG45Score = " + GPG45Score);

        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNode = objectMapper.readTree(GPG45Score);
        String ActualStrength = jsonNode.get("strength").asText();
        String ActualValidity = jsonNode.get("validity").asText();
        String ExpectedValidity = "2";
        String ExpectedStrength = "4";
        System.out.println("ExpectedStrength = " + ExpectedStrength);
        System.out.println("ExpectedValidity = " + ExpectedValidity);
        System.out.println("ActualStrength = " + ActualStrength);
        System.out.println("ActualValidity = " + ActualValidity);
        Assert.assertEquals(ExpectedStrength, ActualStrength);
        Assert.assertEquals(ExpectedValidity, ActualValidity);
    }

    @Then("I should see Verifiable Credentials")
    public void i_should_see_verifiable_credentials() {
        Assert.assertTrue(new UserInformationPage().VerifiableCredential.isDisplayed());
    }

    @Then("Then the {string} error page is displayed")
    public void thenTheSorryWeCannotProveYourIdentityRightNowErrorPageIsDisplayed() {}
}
