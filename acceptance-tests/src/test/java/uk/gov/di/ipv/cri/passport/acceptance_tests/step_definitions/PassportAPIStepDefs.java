package uk.gov.di.ipv.cri.passport.acceptance_tests.step_definitions;

import io.cucumber.java.en.And;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.PassportAPIPage;

import java.io.IOException;
import java.net.URISyntaxException;
import java.text.ParseException;

public class PassportAPIStepDefs extends PassportAPIPage {

    @Given(
            "Passport user has the user identity in the form of a signed JWT string for CRI Id (.*) and row number (.*)$")
    public void passport_user_has_the_user_identity_in_the_form_of_a_signed_jwt_string(
            String criId, Integer LindaDuffExperianRowNumber)
            throws URISyntaxException, IOException, InterruptedException {
        passportUserIdentityAsJwtString(criId, LindaDuffExperianRowNumber);
    }

    @And("Passport user sends a POST request to session endpoint")
    public void passport_user_sends_a_post_request_to_session_end_point()
            throws IOException, InterruptedException {
        passportPostRequestToSessionEndpoint();
    }

    @And("Passport user gets a session-id")
    public void passport_user_gets_a_session_id() {
        getSessionIdForPassport();
    }

    @When("Passport user sends a POST request to Passport endpoint using jsonRequest (.*)$")
    public void passport_user_sends_a_post_request_to_passport_end_point(
            String passportJsonRequestBody) throws IOException, InterruptedException {
        postRequestToPassportEndpoint(passportJsonRequestBody);
    }

    @And("Passport check response should contain Retry value as (.*)$")
    public void passport_check_response_should_contain_Retry_value(Boolean retry) {
        retryValueInPassportCheckResponse(retry);
    }

    @And("Passport user gets authorisation code")
    public void passport_user_gets_authorisation_code() throws IOException, InterruptedException {
        getAuthorisationCodeForPassport();
    }

    @And("Passport user sends a POST request to Access Token endpoint (.*)$")
    public void passport_user_requests_access_token(String CRIId)
            throws IOException, InterruptedException {
        postRequestToAccessTokenEndpointForPassport(CRIId);
    }

    @Then("User requests Passport CRI VC")
    public void user_requests_passport_vc()
            throws IOException, InterruptedException, ParseException {
        postRequestToPassportVCEndpoint();
    }

    @And("Passport VC should contain validityScore (.*) and strengthScore (.*)$")
    public void passport_vc_should_contain_validity_score_and_strength_score(
            String validityScore, String strengthScore)
            throws IOException, InterruptedException, ParseException, URISyntaxException {
        validityScoreAndStrengthScoreInVC(validityScore, strengthScore);
    }
}
