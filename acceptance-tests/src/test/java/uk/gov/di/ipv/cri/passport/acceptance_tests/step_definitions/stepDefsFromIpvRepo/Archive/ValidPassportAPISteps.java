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

import static io.restassured.RestAssured.given;

public class ValidPassportAPISteps extends PassportAPIGlobals {

    String value;
    String accessToken;
    boolean validMessage;
    int validityValue;
    String requestBody =
            "{\n"
                    + "  \"passportNumber\": \"321654987\",\n"
                    + "  \"surname\": \"Decerqueira\",\n"
                    + "  \"forenames\": [\n"
                    + "    \"Kenneth\"\n"
                    + "  ],\n"
                    + "  \"dateOfBirth\": \"1959-08-23\",\n"
                    + "  \"expiryDate\": \"2030-01-01\"\n"
                    + "}";

    @Given("I have Kenneth Decerqueira")
    public void i_have_Kenneth_Decerqueira() {

        // creating POST request for Kenneth Decerqueira with passport body to generate code

        Response passportResponse =
                given().contentType(ContentType.JSON)
                        .queryParam("redirect_uri", redirectURI)
                        .queryParam("client_id", clientId)
                        .body(requestBody)
                        .when()
                        .post(passportPostUrl);

        CodeRoot root = passportResponse.body().as(CodeRoot.class);
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

    @When("I send a GET request with valid UK passport")
    public void i_send_a_GET_request_with_valid_UK_passport() {

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

    @Then("I should get passport valid message and validity value must be 2")
    public void i_should_get_passport_valid_message_and_validity_value_must_be_2() {
        Assert.assertTrue(validMessage);
        System.out.println("validMessage = " + validMessage);
        Assert.assertEquals(2, validityValue);
        System.out.println("validityValue = " + validityValue);
    }
}
