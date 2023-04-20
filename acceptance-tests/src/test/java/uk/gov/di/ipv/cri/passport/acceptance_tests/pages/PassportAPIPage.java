package uk.gov.di.ipv.cri.passport.acceptance_tests.pages;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang3.StringUtils;
import uk.gov.di.ipv.cri.passport.acceptance_tests.model.ClientResponse;
import uk.gov.di.ipv.cri.passport.acceptance_tests.model.DocumentCheckResponse;
import uk.gov.di.ipv.cri.passport.acceptance_tests.service.ConfigurationService;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.text.ParseException;
import java.util.Base64;
import java.util.Map;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class PassportAPIPage extends PassportPageObject {

    private static String SESSION_REQUEST_BODY;
    private static String SESSION_ID;
    private static String STATE;
    private static String AUTHCODE;
    private static String ACCESS_TOKEN;
    private static String VC;
    private static String RETRY;
    private final ObjectMapper objectMapper = new ObjectMapper();

    private final ConfigurationService configurationService =
            new ConfigurationService(System.getenv("ENVIRONMENT"));
    private static final Logger LOGGER = Logger.getLogger(PassportAPIPage.class.getName());

    public String getAuthorisationJwtFromStub(String criId, Integer LindaDuffExperianRowNumber)
            throws URISyntaxException, IOException, InterruptedException {
        String coreStubUrl = configurationService.getCoreStubUrl(false);
        if (coreStubUrl == null) {
            throw new IllegalArgumentException("Environment variable IPV_CORE_STUB_URL is not set");
        }
        return getClaimsForUser(coreStubUrl, criId, LindaDuffExperianRowNumber);
    }

    public void passportUserIdentityAsJwtString(String criId, Integer LindaDuffExperianRowNumber)
            throws URISyntaxException, IOException, InterruptedException {
        String jsonString = getAuthorisationJwtFromStub(criId, LindaDuffExperianRowNumber);
        LOGGER.info("jsonString = " + jsonString);
        String coreStubUrl = configurationService.getCoreStubUrl(false);
        SESSION_REQUEST_BODY = createRequest(coreStubUrl, criId, jsonString);
        LOGGER.info("SESSION_REQUEST_BODY = " + SESSION_REQUEST_BODY);
    }

    public void passportPostRequestToSessionEndpoint() throws IOException, InterruptedException {
        String privateApiGatewayUrl = configurationService.getPrivateAPIEndpoint();
        LOGGER.info("getPrivateAPIEndpoint() ==> " + privateApiGatewayUrl);
        String requestString =
                String.valueOf(
                        new ObjectMapper()
                                .readValue(SESSION_REQUEST_BODY, Map.class)
                                .get("request"));
        LOGGER.info("REQUEST STRING ==> " + requestString);
        HttpRequest request =
                HttpRequest.newBuilder()
                        .uri(URI.create(privateApiGatewayUrl + "/initialise-session"))
                        .setHeader("Accept", "application/json")
                        .setHeader("Content-Type", "application/json")
                        .setHeader("X-Forwarded-For", "123456789")
                        .setHeader("client_id", "ipv-core-stub")
                        .POST(HttpRequest.BodyPublishers.ofString(requestString))
                        .build();
        String sessionResponse = sendHttpRequest(request).body();
        LOGGER.info("sessionResponse = " + sessionResponse);
        Map<String, Object> deserialisedResponse =
                objectMapper.readValue(sessionResponse, new TypeReference<>() {});
        SESSION_ID = (String) deserialisedResponse.get("passportSessionId");
    }

    public void getSessionIdForPassport() {
        LOGGER.info("SESSION_ID = " + SESSION_ID);
        assertTrue(StringUtils.isNotBlank(SESSION_ID));
    }

    public void postRequestToPassportEndpoint(String passportJsonRequestBody)
            throws IOException, InterruptedException {
        String privateApiGatewayUrl = configurationService.getPrivateAPIEndpoint();
        JsonNode passportJson =
                objectMapper.readTree(
                        new File("src/test/resources/Data/" + passportJsonRequestBody + ".json"));
        String passportInputJsonString = passportJson.toString();
        HttpRequest request =
                HttpRequest.newBuilder()
                        .uri(URI.create(privateApiGatewayUrl + "/check-passport"))
                        .setHeader("Accept", "application/json")
                        .setHeader("Content-Type", "application/json")
                        .setHeader("passport_session_id", SESSION_ID)
                        .POST(HttpRequest.BodyPublishers.ofString(passportInputJsonString))
                        .build();
        LOGGER.info("passport RequestBody = " + passportInputJsonString);
        String passportCheckResponse = sendHttpRequest(request).body();
        LOGGER.info("passportCheckResponse = " + passportCheckResponse);
        DocumentCheckResponse documentCheckResponse =
                objectMapper.readValue(passportCheckResponse, DocumentCheckResponse.class);
        RETRY = documentCheckResponse.getResult();
        LOGGER.info("RETRY = " + RETRY);
    }

    public void retryValueInPassportCheckResponse(Boolean retry) {
        if (retry) {
            if (RETRY.equals("retry")) {
                LOGGER.info("Success");
            } else {
                fail("Failure should not retry");
            }
        } else {
            if (RETRY.equals("finish")) {
                LOGGER.info("Success");
            } else {
                fail("Should have retried");
            }
        }
    }

    public void getAuthorisationCodeForPassport() throws IOException, InterruptedException {
        String privateApiGatewayUrl = configurationService.getPrivateAPIEndpoint();
        String coreStubUrl = configurationService.getCoreStubUrl(false);

        HttpRequest request =
                HttpRequest.newBuilder()
                        .uri(URI.create(privateApiGatewayUrl + "/build-client-oauth-response"))
                        .setHeader("Accept", "application/json")
                        .setHeader("Content-Type", "application/json")
                        .setHeader("passport_session_id", SESSION_ID)
                        .POST(HttpRequest.BodyPublishers.noBody())
                        .build();
        String authCallResponse = sendHttpRequest(request).body();
        LOGGER.info("authCallResponse = " + authCallResponse);
        ClientResponse deserialisedResponse =
                objectMapper.readValue(authCallResponse, ClientResponse.class);
        String redirectUrl = deserialisedResponse.getClient().getRedirectUrl();
        AUTHCODE = redirectUrl.substring(redirectUrl.indexOf("?code=") + 6);
        LOGGER.info("authorizationCode = " + AUTHCODE);
    }

    public void postRequestToAccessTokenEndpointForPassport(String criId)
            throws IOException, InterruptedException {
        String accessTokenRequestBody = getAccessTokenRequest(criId);
        LOGGER.info("Access Token Request Body = " + accessTokenRequestBody);
        String publicApiGatewayUrl = configurationService.getPublicAPIEndpoint();
        LOGGER.info("getPublicAPIEndpoint() ==> " + publicApiGatewayUrl);
        HttpRequest request =
                HttpRequest.newBuilder()
                        .uri(URI.create(publicApiGatewayUrl + "/token"))
                        .setHeader("Accept", "application/json")
                        .setHeader("Content-Type", "application/json")
                        .setHeader("x-api-key", configurationService.getPublicApiGatewayKey())
                        .POST(HttpRequest.BodyPublishers.ofString(accessTokenRequestBody))
                        .build();
        String accessTokenPostCallResponse = sendHttpRequest(request).body();
        LOGGER.info("accessTokenPostCallResponse = " + accessTokenPostCallResponse);
        Map<String, String> deserialisedResponse =
                objectMapper.readValue(accessTokenPostCallResponse, new TypeReference<>() {});
        ACCESS_TOKEN = deserialisedResponse.get("access_token");
    }

    public String postRequestToPassportVCEndpoint()
            throws IOException, InterruptedException, ParseException {
        String publicApiGatewayUrl = configurationService.getPublicAPIEndpoint();
        HttpRequest request =
                HttpRequest.newBuilder()
                        .uri(URI.create(publicApiGatewayUrl + "/credentials/issue"))
                        .setHeader("Accept", "application/json")
                        .setHeader("Content-Type", "application/json")
                        .setHeader("Authorization", "Bearer " + ACCESS_TOKEN)
                        .setHeader("x-api-key", configurationService.getPublicApiGatewayKey())
                        .POST(HttpRequest.BodyPublishers.ofString(""))
                        .build();
        String requestPassportVCResponse = sendHttpRequest(request).body();
        LOGGER.info("requestPassportVCResponse = " + requestPassportVCResponse);
        SignedJWT signedJWT = SignedJWT.parse(requestPassportVCResponse);
        VC = signedJWT.getJWTClaimsSet().toString();
        return signedJWT.getJWTClaimsSet().toString();
    }

    public void validityScoreAndStrengthScoreInVC(String validityScore, String strengthScore)
            throws URISyntaxException, IOException, InterruptedException, ParseException {
        String passportCriVc = VC;
        if (null == VC) {
            passportCriVc = postRequestToPassportVCEndpoint();
        }
        scoreIs(validityScore, strengthScore, passportCriVc);
    }

    private String getClaimsForUser(String baseUrl, String criId, int userDataRowNumber)
            throws URISyntaxException, IOException, InterruptedException {

        var url =
                new URI(
                        baseUrl
                                + "/backend/generateInitialClaimsSet?cri="
                                + criId
                                + "&rowNumber="
                                + userDataRowNumber);

        LOGGER.info("URL =>> " + url);

        HttpRequest request =
                HttpRequest.newBuilder()
                        .uri(url)
                        .GET()
                        .setHeader(
                                "Authorization",
                                getBasicAuthenticationHeader(
                                        configurationService.getCoreStubUsername(),
                                        configurationService.getCoreStubPassword()))
                        .build();
        return sendHttpRequest(request).body();
    }

    private String createRequest(String baseUrl, String criId, String jsonString)
            throws URISyntaxException, IOException, InterruptedException {

        URI uri = new URI(baseUrl + "/backend/createSessionRequest?cri=" + criId);
        LOGGER.info("URL =>> " + uri);

        HttpRequest request =
                HttpRequest.newBuilder()
                        .uri(uri)
                        .setHeader("Accept", "application/json")
                        .setHeader("Content-Type", "application/json")
                        .setHeader(
                                "Authorization",
                                getBasicAuthenticationHeader(
                                        configurationService.getCoreStubUsername(),
                                        configurationService.getCoreStubPassword()))
                        .POST(HttpRequest.BodyPublishers.ofString(jsonString))
                        .build();

        return sendHttpRequest(request).body();
    }

    private HttpResponse<String> sendHttpRequest(HttpRequest request)
            throws IOException, InterruptedException {
        HttpClient client = HttpClient.newBuilder().build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        return response;
    }

    private static final String getBasicAuthenticationHeader(String username, String password) {
        String valueToEncode = username + ":" + password;
        return "Basic " + Base64.getEncoder().encodeToString(valueToEncode.getBytes());
    }

    private String getAccessTokenRequest(String criId) throws IOException, InterruptedException {
        String coreStubUrl = configurationService.getCoreStubUrl(false);

        HttpRequest request =
                HttpRequest.newBuilder()
                        .uri(
                                URI.create(
                                        coreStubUrl
                                                + "/backend/createTokenRequestPrivateKeyJWT?authorization_code="
                                                + AUTHCODE
                                                + "&cri="
                                                + criId))
                        .setHeader("Accept", "application/json")
                        .setHeader("Content-Type", "application/json")
                        .setHeader(
                                "Authorization",
                                getBasicAuthenticationHeader(
                                        configurationService.getCoreStubUsername(),
                                        configurationService.getCoreStubPassword()))
                        .GET()
                        .build();
        return sendHttpRequest(request).body();
    }
}
