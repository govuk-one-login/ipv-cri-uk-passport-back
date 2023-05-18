package uk.gov.di.ipv.cri.passport.acceptance_tests.step_definitions.stepDefsFromIpvRepo.Archive;

import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import io.restassured.path.json.JsonPath;
import io.restassured.response.Response;
import org.junit.Assert;
import uk.gov.di.ipv.cri.passport.acceptance_tests.POJOFromIpvCoreRepo.CodeRoot;
import uk.gov.di.ipv.cri.passport.acceptance_tests.POJOFromIpvCoreRepo.PassportCheckResult;
import uk.gov.di.ipv.cri.passport.acceptance_tests.utilities.UtilitiesFromIpvRepo.PassportAPIGlobals;

public class InvalidPassportAPISteps extends PassportAPIGlobals {

    String value;
    String accessToken;
    boolean validMessage;
    int validityValue;
    String alBundyRequestBody =
            "{\n"
                    + "  \"passportNumber\": \"884159121\",\n"
                    + "  \"surname\": \"Bundy\",\n"
                    + "  \"forenames\": [\n"
                    + "    \"Al\"\n"
                    + "  ],\n"
                    + "  \"dateOfBirth\": \"1940-02-25\",\n"
                    + "  \"expiryDate\": \"2022-03-01\"\n"
                    + "}";

    @Given("I have Al Bundy")
    public void i_have_Al_Bundy() {

        // creating POST request for Al Bundy to generate code

        Response alBundyPassportResponse =
                RestAssured.given()
                        .contentType(ContentType.JSON)
                        .queryParam("redirect_uri", redirectURI)
                        .queryParam("client_id", clientId)
                        .body(alBundyRequestBody)
                        .when()
                        .post(passportPostUrl);

        CodeRoot root = alBundyPassportResponse.body().as(CodeRoot.class);
        value = root.getCode().getValue();

        // creating POST request with code value to generate access_token

        Response tokenResponse =
                RestAssured.given()
                        .contentType("application/x-www-form-urlencoded; charset=utf-8")
                        .formParam("code", value)
                        .formParam("redirect_uri", redirect_uri)
                        .formParam("grant_type", grant_type)
                        .formParam("client_id", client_id)
                        .when()
                        .post(tokenPostUrl);

        JsonPath tokenPath = tokenResponse.jsonPath();
        accessToken = tokenPath.get("access_token");
    }

    @When("I send a GET request with invalid UK passport")
    public void i_send_a_GET_request_with_invalid_UK_passport() {
        Response credentialResponse =
                RestAssured.given()
                        .accept(ContentType.JSON)
                        .header("Authorization", "Bearer " + accessToken)
                        .when()
                        .get(credentialGetUrl);

        PassportCheckResult result = credentialResponse.body().as(PassportCheckResult.class);
        validMessage = result.getAttributes().getDcsResponse().isValid();
        validityValue = result.getGpg45Score().getEvidence().getValidity();
    }

    @Then("I should get passport invalid message and validity value must be {int}")
    public void i_should_get_passport_invalid_message_and_validity_value_must_be(Integer int1) {
        Assert.assertFalse(validMessage);
        System.out.println("validMessage = " + validMessage);
        Assert.assertEquals(0, validityValue);
        System.out.println("validityValue = " + validityValue);
    }
}
