package uk.gov.di.ipv.cri.passport.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.passport.domain.DcsResponse;
import uk.gov.di.ipv.cri.passport.domain.DcsSignedEncryptedResponse;
import uk.gov.di.ipv.cri.passport.domain.PassportFormRequest;
import uk.gov.di.ipv.cri.passport.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.exceptions.EmptyDcsResponseException;
import uk.gov.di.ipv.cri.passport.persistence.item.PassportCheckDao;
import uk.gov.di.ipv.cri.passport.service.AuthorizationCodeService;
import uk.gov.di.ipv.cri.passport.service.ConfigurationService;
import uk.gov.di.ipv.cri.passport.service.DcsCryptographyService;
import uk.gov.di.ipv.cri.passport.service.PassportService;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.time.LocalDate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PassportHandlerTest {

    public static final String PASSPORT_NUMBER = "1234567890";
    public static final String SURNAME = "Tattsyrup";
    public static final String[] FORENAMES = {"Tubbs"};
    public static final String DATE_OF_BIRTH = "1984-09-28";
    public static final String EXPIRY_DATE = "2024-09-03";
    private final ObjectMapper objectMapper =
            new ObjectMapper().registerModule(new JavaTimeModule());
    private final Map<String, String> validPassportFormData =
            Map.of(
                    "passportNumber", PASSPORT_NUMBER,
                    "surname", SURNAME,
                    "forenames", Arrays.toString(FORENAMES),
                    "dateOfBirth", DATE_OF_BIRTH,
                    "expiryDate", EXPIRY_DATE);

    private final DcsResponse validDcsResponse =
            new DcsResponse(UUID.randomUUID(), UUID.randomUUID(), false, true, null);

    private final PassportFormRequest passportFormRequest =
            new PassportFormRequest(
                    PASSPORT_NUMBER,
                    SURNAME,
                    FORENAMES,
                    LocalDate.parse(DATE_OF_BIRTH),
                    LocalDate.parse(EXPIRY_DATE));

    @Mock Context context;
    @Mock PassportService passportService;
    @Mock AuthorizationCodeService authorizationCodeService;
    @Mock ConfigurationService configurationService;
    @Mock DcsCryptographyService dcsCryptographyService;
    @Mock JWSObject jwsObject;

    private PassportHandler underTest;
    private AuthorizationCode authorizationCode;

    @BeforeEach
    void setUp() {
        authorizationCode = new AuthorizationCode();

        underTest =
                new PassportHandler(
                        passportService,
                        authorizationCodeService,
                        configurationService,
                        dcsCryptographyService);
    }

    @Test
    void shouldReturn200WithCorrectFormData()
            throws IOException, CertificateException, NoSuchAlgorithmException,
                    InvalidKeySpecException, JOSEException, ParseException,
                    EmptyDcsResponseException {
        DcsSignedEncryptedResponse dcsSignedEncryptedResponse =
                new DcsSignedEncryptedResponse("TEST_PAYLOAD");
        when(passportService.dcsPassportCheck(any(JWSObject.class)))
                .thenReturn(dcsSignedEncryptedResponse);
        when(dcsCryptographyService.preparePayload(any(PassportFormRequest.class)))
                .thenReturn(jwsObject);
        when(dcsCryptographyService.unwrapDcsResponse(any(DcsSignedEncryptedResponse.class)))
                .thenReturn(validDcsResponse);
        when(authorizationCodeService.generateAuthorizationCode()).thenReturn(authorizationCode);

        var event = new APIGatewayProxyRequestEvent();
        Map<String, String> params = new HashMap<>();
        params.put(OAuth2RequestParams.REDIRECT_URI, "http://example.com");
        params.put(OAuth2RequestParams.CLIENT_ID, "12345");
        params.put(OAuth2RequestParams.RESPONSE_TYPE, "code");
        params.put(OAuth2RequestParams.SCOPE, "openid");
        event.setQueryStringParameters(params);
        event.setBody(objectMapper.writeValueAsString(validPassportFormData));

        var response = underTest.handleRequest(event, context);

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldReturnAuthResponseOnSuccessfulOauthRequest()
            throws IOException, CertificateException, NoSuchAlgorithmException,
                    InvalidKeySpecException, JOSEException, ParseException,
                    EmptyDcsResponseException {
        DcsSignedEncryptedResponse dcsSignedEncryptedResponse =
                new DcsSignedEncryptedResponse("TEST_PAYLOAD");
        PassportCheckDao passportCheckDao =
                new PassportCheckDao("UUID", passportFormRequest, validDcsResponse);
        when(passportService.dcsPassportCheck(any(JWSObject.class)))
                .thenReturn(dcsSignedEncryptedResponse);
        when(dcsCryptographyService.preparePayload(any(PassportFormRequest.class)))
                .thenReturn(jwsObject);
        when(dcsCryptographyService.unwrapDcsResponse(any(DcsSignedEncryptedResponse.class)))
                .thenReturn(validDcsResponse);
        when(authorizationCodeService.generateAuthorizationCode()).thenReturn(authorizationCode);

        var event = new APIGatewayProxyRequestEvent();
        Map<String, String> params = new HashMap<>();
        params.put(OAuth2RequestParams.REDIRECT_URI, "http://example.com");
        params.put(OAuth2RequestParams.CLIENT_ID, "12345");
        params.put(OAuth2RequestParams.RESPONSE_TYPE, "code");
        params.put(OAuth2RequestParams.SCOPE, "openid");
        event.setQueryStringParameters(params);
        event.setBody(objectMapper.writeValueAsString(validPassportFormData));

        var response = underTest.handleRequest(event, context);

        ObjectMapper objectMapper = new ObjectMapper();
        Map<String, Object> responseBody = objectMapper.readValue(response.getBody(), Map.class);
        Map<String, String> authCode = (Map) responseBody.get("code");

        ArgumentCaptor<PassportCheckDao> persistedDcsResponseItem =
                ArgumentCaptor.forClass(PassportCheckDao.class);
        verify(passportService).persistDcsResponse(persistedDcsResponseItem.capture());

        verify(authorizationCodeService)
                .persistAuthorizationCode(
                        authCode.get("value"), persistedDcsResponseItem.getValue().getResourceId());
        assertEquals(authorizationCode.toString(), authCode.get("value"));
    }

    @Test
    void shouldReturn400OnMissingRedirectUriParam() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Map<String, String> params = new HashMap<>();
        params.put(OAuth2RequestParams.CLIENT_ID, "12345");
        params.put(OAuth2RequestParams.RESPONSE_TYPE, "code");
        params.put(OAuth2RequestParams.SCOPE, "openid");
        event.setQueryStringParameters(params);
        event.setBody(objectMapper.writeValueAsString(validPassportFormData));

        var response = underTest.handleRequest(event, context);

        ObjectMapper objectMapper = new ObjectMapper();
        Map responseBody = objectMapper.readValue(response.getBody(), Map.class);

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS.getCode(),
                responseBody.get("code"));
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS.getMessage(),
                responseBody.get("message"));
    }

    @Test
    void shouldReturn400OnMissingClientIdParam() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Map<String, String> params = new HashMap<>();
        params.put(OAuth2RequestParams.REDIRECT_URI, "http://example.com");
        params.put(OAuth2RequestParams.RESPONSE_TYPE, "code");
        params.put(OAuth2RequestParams.SCOPE, "openid");
        event.setQueryStringParameters(params);
        event.setBody(objectMapper.writeValueAsString(validPassportFormData));

        var response = underTest.handleRequest(event, context);

        ObjectMapper objectMapper = new ObjectMapper();
        Map responseBody = objectMapper.readValue(response.getBody(), Map.class);

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS.getCode(),
                responseBody.get("code"));
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS.getMessage(),
                responseBody.get("message"));
    }

    @Test
    void shouldReturn400OnMissingResponseTypeParam() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Map<String, String> params = new HashMap<>();
        params.put(OAuth2RequestParams.REDIRECT_URI, "http://example.com");
        params.put(OAuth2RequestParams.CLIENT_ID, "12345");
        params.put(OAuth2RequestParams.SCOPE, "openid");
        event.setQueryStringParameters(params);
        event.setBody(objectMapper.writeValueAsString(validPassportFormData));

        var response = underTest.handleRequest(event, context);

        ObjectMapper objectMapper = new ObjectMapper();
        Map responseBody = objectMapper.readValue(response.getBody(), Map.class);

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS.getCode(),
                responseBody.get("code"));
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS.getMessage(),
                responseBody.get("message"));
    }

    @Test
    void shouldReturn400OnMissingScopeParam() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Map<String, String> params = new HashMap<>();
        params.put(OAuth2RequestParams.REDIRECT_URI, "http://example.com");
        params.put(OAuth2RequestParams.CLIENT_ID, "12345");
        params.put(OAuth2RequestParams.RESPONSE_TYPE, "code");
        event.setQueryStringParameters(params);
        event.setBody(objectMapper.writeValueAsString(validPassportFormData));

        var response = underTest.handleRequest(event, context);

        ObjectMapper objectMapper = new ObjectMapper();
        Map responseBody = objectMapper.readValue(response.getBody(), Map.class);

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS.getCode(),
                responseBody.get("code"));
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS.getMessage(),
                responseBody.get("message"));
    }

    @Test
    void shouldReturn400OnMissingQueryParameters() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        event.setBody(objectMapper.writeValueAsString(validPassportFormData));

        APIGatewayProxyResponseEvent response = underTest.handleRequest(event, context);

        ObjectMapper objectMapper = new ObjectMapper();
        Map responseBody = objectMapper.readValue(response.getBody(), Map.class);

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.MISSING_QUERY_PARAMETERS.getCode(), responseBody.get("code"));
        assertEquals(
                ErrorResponse.MISSING_QUERY_PARAMETERS.getMessage(), responseBody.get("message"));
    }

    @Test
    void shouldReturn400IfDataIsMissing() throws JsonProcessingException {
        var formFields = validPassportFormData.keySet();
        for (String keyToRemove : formFields) {
            var event = new APIGatewayProxyRequestEvent();
            Map<String, String> params = new HashMap<>();
            params.put(OAuth2RequestParams.REDIRECT_URI, "http://example.com");
            params.put(OAuth2RequestParams.CLIENT_ID, "12345");
            params.put(OAuth2RequestParams.RESPONSE_TYPE, "code");
            params.put(OAuth2RequestParams.SCOPE, "openid");
            event.setQueryStringParameters(params);
            event.setBody(
                    objectMapper.writeValueAsString(
                            new HashMap<>(validPassportFormData).remove(keyToRemove)));

            var response = underTest.handleRequest(event, context);
            var responseBody = objectMapper.readValue(response.getBody(), Map.class);

            assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
            assertEquals(
                    ErrorResponse.FAILED_TO_PARSE_PASSPORT_FORM_DATA.getCode(),
                    responseBody.get("code"));
            assertEquals(
                    ErrorResponse.FAILED_TO_PARSE_PASSPORT_FORM_DATA.getMessage(),
                    responseBody.get("message"));
        }
    }

    @Test
    void shouldReturn400IfDateStringsAreWrongFormat() throws JsonProcessingException {
        var mangledDateInput = new HashMap<>(validPassportFormData);
        mangledDateInput.put("dateOfBirth", "28-09-1984");

        var event = new APIGatewayProxyRequestEvent();
        Map<String, String> params = new HashMap<>();
        params.put(OAuth2RequestParams.REDIRECT_URI, "http://example.com");
        params.put(OAuth2RequestParams.CLIENT_ID, "12345");
        params.put(OAuth2RequestParams.RESPONSE_TYPE, "code");
        params.put(OAuth2RequestParams.SCOPE, "openid");
        event.setQueryStringParameters(params);
        event.setBody(objectMapper.writeValueAsString(mangledDateInput));

        var response = underTest.handleRequest(event, context);
        var responseBody = objectMapper.readValue(response.getBody(), Map.class);

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_PASSPORT_FORM_DATA.getCode(),
                responseBody.get("code"));
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_PASSPORT_FORM_DATA.getMessage(),
                responseBody.get("message"));
    }

    @Test
    void shouldPersistPassportCheckDao()
            throws IOException, CertificateException, NoSuchAlgorithmException,
                    InvalidKeySpecException, JOSEException, ParseException,
                    EmptyDcsResponseException {
        DcsSignedEncryptedResponse dcsSignedEncryptedResponse =
                new DcsSignedEncryptedResponse("TEST_PAYLOAD");
        when(passportService.dcsPassportCheck(any(JWSObject.class)))
                .thenReturn(dcsSignedEncryptedResponse);
        when(dcsCryptographyService.preparePayload(any(PassportFormRequest.class)))
                .thenReturn(jwsObject);
        when(dcsCryptographyService.unwrapDcsResponse(any(DcsSignedEncryptedResponse.class)))
                .thenReturn(validDcsResponse);

        when(authorizationCodeService.generateAuthorizationCode()).thenReturn(authorizationCode);

        var event = new APIGatewayProxyRequestEvent();
        Map<String, String> params = new HashMap<>();
        params.put(OAuth2RequestParams.REDIRECT_URI, "http://example.com");
        params.put(OAuth2RequestParams.CLIENT_ID, "12345");
        params.put(OAuth2RequestParams.RESPONSE_TYPE, "code");
        params.put(OAuth2RequestParams.SCOPE, "openid");
        event.setQueryStringParameters(params);
        event.setBody(objectMapper.writeValueAsString(validPassportFormData));

        underTest.handleRequest(event, context);

        ArgumentCaptor<PassportCheckDao> persistedPassportCheckDao =
                ArgumentCaptor.forClass(PassportCheckDao.class);

        verify(passportService).persistDcsResponse(persistedPassportCheckDao.capture());
        assertEquals(
                validPassportFormData.get("passportNumber"),
                persistedPassportCheckDao.getValue().getPassportFormRequest().getPassportNumber());
        assertEquals(validDcsResponse, persistedPassportCheckDao.getValue().getDcsResponse());
    }

    @Test
    void shouldPersistAuthCode()
            throws IOException, CertificateException, NoSuchAlgorithmException,
                    InvalidKeySpecException, JOSEException, ParseException,
                    EmptyDcsResponseException {
        DcsSignedEncryptedResponse dcsSignedEncryptedResponse =
                new DcsSignedEncryptedResponse("TEST_PAYLOAD");
        when(passportService.dcsPassportCheck(any(JWSObject.class)))
                .thenReturn(dcsSignedEncryptedResponse);
        when(dcsCryptographyService.preparePayload(any(PassportFormRequest.class)))
                .thenReturn(jwsObject);
        PassportCheckDao passportCheckDao =
                new PassportCheckDao("UUID", passportFormRequest, validDcsResponse);
        when(dcsCryptographyService.unwrapDcsResponse(any(DcsSignedEncryptedResponse.class)))
                .thenReturn(validDcsResponse);

        when(authorizationCodeService.generateAuthorizationCode()).thenReturn(authorizationCode);

        var event = new APIGatewayProxyRequestEvent();
        Map<String, String> params = new HashMap<>();
        params.put(OAuth2RequestParams.REDIRECT_URI, "http://example.com");
        params.put(OAuth2RequestParams.CLIENT_ID, "12345");
        params.put(OAuth2RequestParams.RESPONSE_TYPE, "code");
        params.put(OAuth2RequestParams.SCOPE, "openid");
        event.setQueryStringParameters(params);
        event.setBody(objectMapper.writeValueAsString(validPassportFormData));

        underTest.handleRequest(event, context);

        ArgumentCaptor<String> authCodeArgumentCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> resourceIdArgumentCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<PassportCheckDao> dcsResponseItemArgumentCaptor =
                ArgumentCaptor.forClass(PassportCheckDao.class);
        verify(passportService).persistDcsResponse(dcsResponseItemArgumentCaptor.capture());

        verify(authorizationCodeService)
                .persistAuthorizationCode(
                        authCodeArgumentCaptor.capture(), resourceIdArgumentCaptor.capture());

        assertEquals(authorizationCode.toString(), authCodeArgumentCaptor.getValue());
        assertEquals(
                dcsResponseItemArgumentCaptor.getValue().getResourceId(),
                resourceIdArgumentCaptor.getValue());
    }
}
