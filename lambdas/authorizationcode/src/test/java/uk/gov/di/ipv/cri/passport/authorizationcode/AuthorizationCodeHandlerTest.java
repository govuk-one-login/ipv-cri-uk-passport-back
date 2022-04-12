package uk.gov.di.ipv.cri.passport.authorizationcode;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
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
import uk.gov.di.ipv.cri.passport.authorizationcode.validation.AuthRequestValidator;
import uk.gov.di.ipv.cri.passport.library.domain.DcsResponse;
import uk.gov.di.ipv.cri.passport.library.domain.DcsSignedEncryptedResponse;
import uk.gov.di.ipv.cri.passport.library.domain.PassportAttributes;
import uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.Evidence;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.library.exceptions.EmptyDcsResponseException;
import uk.gov.di.ipv.cri.passport.library.persistence.item.PassportCheckDao;
import uk.gov.di.ipv.cri.passport.library.service.AuthorizationCodeService;
import uk.gov.di.ipv.cri.passport.library.service.ConfigurationService;
import uk.gov.di.ipv.cri.passport.library.service.DcsCryptographyService;
import uk.gov.di.ipv.cri.passport.library.service.PassportService;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthorizationCodeHandlerTest {
    private static final Map<String, String> TEST_EVENT_HEADERS = Map.of("ipv-session-id", "12345");
    public static final String PASSPORT_NUMBER = "1234567890";
    public static final String SURNAME = "Tattsyrup";
    public static final List<String> FORENAMES = List.of("Tubbs");
    public static final String DATE_OF_BIRTH = "1984-09-28";
    public static final String EXPIRY_DATE = "2024-09-03";
    public static final Evidence VALID_GPG45_SCORE = new Evidence(4, 2);
    public static final Evidence INVALID_GPG45_SCORE = new Evidence(4, 0);
    private static final Map<String, String> VALID_QUERY_PARAMS =
            Map.of(
                    OAuth2RequestParams.REDIRECT_URI, "http://example.com",
                    OAuth2RequestParams.CLIENT_ID, "12345",
                    OAuth2RequestParams.RESPONSE_TYPE, "code",
                    OAuth2RequestParams.SCOPE, "openid");

    private final ObjectMapper objectMapper =
            new ObjectMapper().registerModule(new JavaTimeModule());
    private final Map<String, String> validPassportFormData =
            Map.of(
                    "passportNumber", PASSPORT_NUMBER,
                    "surname", SURNAME,
                    "forenames", FORENAMES.toString(),
                    "dateOfBirth", DATE_OF_BIRTH,
                    "expiryDate", EXPIRY_DATE);

    private final DcsResponse validDcsResponse =
            new DcsResponse(
                    UUID.randomUUID().toString(), UUID.randomUUID().toString(), false, true, null);

    private final DcsResponse invalidDcsResponse =
            new DcsResponse(
                    UUID.randomUUID().toString(), UUID.randomUUID().toString(), false, false, null);

    @Mock Context context;
    @Mock PassportService passportService;
    @Mock AuthorizationCodeService authorizationCodeService;
    @Mock ConfigurationService configurationService;
    @Mock DcsCryptographyService dcsCryptographyService;
    @Mock AuthRequestValidator authRequestValidator;
    @Mock JWSObject jwsObject;

    private AuthorizationCodeHandler underTest;
    private AuthorizationCode authorizationCode;

    @BeforeEach
    void setUp() {
        authorizationCode = new AuthorizationCode();

        underTest =
                new AuthorizationCodeHandler(
                        passportService,
                        authorizationCodeService,
                        configurationService,
                        dcsCryptographyService,
                        authRequestValidator);
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
        when(dcsCryptographyService.preparePayload(any(PassportAttributes.class)))
                .thenReturn(jwsObject);
        when(dcsCryptographyService.unwrapDcsResponse(any(DcsSignedEncryptedResponse.class)))
                .thenReturn(validDcsResponse);
        when(authorizationCodeService.generateAuthorizationCode()).thenReturn(authorizationCode);
        when(authRequestValidator.validateRequest(any())).thenReturn(Optional.empty());

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
        when(passportService.dcsPassportCheck(any(JWSObject.class)))
                .thenReturn(dcsSignedEncryptedResponse);
        when(dcsCryptographyService.preparePayload(any(PassportAttributes.class)))
                .thenReturn(jwsObject);
        when(dcsCryptographyService.unwrapDcsResponse(any(DcsSignedEncryptedResponse.class)))
                .thenReturn(validDcsResponse);
        when(authorizationCodeService.generateAuthorizationCode()).thenReturn(authorizationCode);
        when(authRequestValidator.validateRequest(any())).thenReturn(Optional.empty());

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
        Map<String, Map<String, String>> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});
        Map<String, String> authCode = responseBody.get("code");

        ArgumentCaptor<PassportCheckDao> persistedDcsResponseItem =
                ArgumentCaptor.forClass(PassportCheckDao.class);
        verify(passportService).persistDcsResponse(persistedDcsResponseItem.capture());

        verify(authorizationCodeService)
                .persistAuthorizationCode(
                        authCode.get("value"),
                        persistedDcsResponseItem.getValue().getResourceId(),
                        params.get(OAuth2RequestParams.REDIRECT_URI));
        assertEquals(authorizationCode.toString(), authCode.get("value"));
    }

    @Test
    void shouldReturn400IfRequestFailsValidation() throws Exception {
        when(authRequestValidator.validateRequest(anyMap()))
                .thenReturn(Optional.of(ErrorResponse.MISSING_QUERY_PARAMETERS));

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(new HashMap<>());
        event.setBody(objectMapper.writeValueAsString(validPassportFormData));

        var response = underTest.handleRequest(event, context);

        ObjectMapper objectMapper = new ObjectMapper();
        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(ErrorResponse.MISSING_QUERY_PARAMETERS.getCode(), responseBody.get("code"));
        assertEquals(
                ErrorResponse.MISSING_QUERY_PARAMETERS.getMessage(), responseBody.get("message"));

        verify(authorizationCodeService, never())
                .persistAuthorizationCode(anyString(), anyString(), anyString());
    }

    @Test
    void shouldReturn400IfDataIsMissing() throws JsonProcessingException {
        when(authRequestValidator.validateRequest(anyMap())).thenReturn(Optional.empty());
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
        when(authRequestValidator.validateRequest(anyMap())).thenReturn(Optional.empty());

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
    void shouldReturn500OnDcsErrorResponse() throws Exception {
        DcsSignedEncryptedResponse dcsSignedEncryptedResponse =
                new DcsSignedEncryptedResponse("TEST_PAYLOAD");
        when(passportService.dcsPassportCheck(any(JWSObject.class)))
                .thenReturn(dcsSignedEncryptedResponse);
        when(dcsCryptographyService.preparePayload(any(PassportAttributes.class)))
                .thenReturn(jwsObject);
        when(authRequestValidator.validateRequest(anyMap())).thenReturn(Optional.empty());

        DcsResponse errorDcsResponse =
                new DcsResponse(
                        UUID.randomUUID().toString(),
                        UUID.randomUUID().toString(),
                        true,
                        false,
                        List.of("Test DCS error message"));
        when(dcsCryptographyService.unwrapDcsResponse(any(DcsSignedEncryptedResponse.class)))
                .thenReturn(errorDcsResponse);

        var event = new APIGatewayProxyRequestEvent();
        Map<String, String> params = new HashMap<>();
        params.put(OAuth2RequestParams.REDIRECT_URI, "http://example.com");
        params.put(OAuth2RequestParams.CLIENT_ID, "12345");
        params.put(OAuth2RequestParams.RESPONSE_TYPE, "code");
        params.put(OAuth2RequestParams.SCOPE, "openid");
        event.setQueryStringParameters(params);
        event.setBody(objectMapper.writeValueAsString(validPassportFormData));

        var response = underTest.handleRequest(event, context);

        var responseBody = objectMapper.readValue(response.getBody(), Map.class);

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals(ErrorResponse.DCS_RETURNED_AN_ERROR.getCode(), responseBody.get("code"));
        assertEquals(ErrorResponse.DCS_RETURNED_AN_ERROR.getMessage(), responseBody.get("message"));
    }

    @Test
    void shouldPersistPassportCheckDaoWithValidGpg45Score()
            throws IOException, CertificateException, NoSuchAlgorithmException,
                    InvalidKeySpecException, JOSEException, ParseException,
                    EmptyDcsResponseException {
        DcsSignedEncryptedResponse dcsSignedEncryptedResponse =
                new DcsSignedEncryptedResponse("TEST_PAYLOAD");
        when(passportService.dcsPassportCheck(any(JWSObject.class)))
                .thenReturn(dcsSignedEncryptedResponse);
        when(dcsCryptographyService.preparePayload(any(PassportAttributes.class)))
                .thenReturn(jwsObject);
        when(dcsCryptographyService.unwrapDcsResponse(any(DcsSignedEncryptedResponse.class)))
                .thenReturn(validDcsResponse);
        when(authorizationCodeService.generateAuthorizationCode()).thenReturn(authorizationCode);
        when(authRequestValidator.validateRequest(anyMap())).thenReturn(Optional.empty());

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
                persistedPassportCheckDao.getValue().getAttributes().getPassportNumber());
        assertEquals(
                VALID_GPG45_SCORE.getStrength(),
                persistedPassportCheckDao.getValue().getGpg45Score().getStrength());
        assertEquals(
                VALID_GPG45_SCORE.getValidity(),
                persistedPassportCheckDao.getValue().getGpg45Score().getValidity());
        assertEquals(
                validDcsResponse,
                persistedPassportCheckDao.getValue().getAttributes().getDcsResponse());
    }

    @Test
    void shouldPersistPassportCheckDaoWithInValidGpg45Score()
            throws IOException, CertificateException, NoSuchAlgorithmException,
                    InvalidKeySpecException, JOSEException, ParseException,
                    EmptyDcsResponseException {
        DcsSignedEncryptedResponse dcsSignedEncryptedResponse =
                new DcsSignedEncryptedResponse("TEST_PAYLOAD");
        when(passportService.dcsPassportCheck(any(JWSObject.class)))
                .thenReturn(dcsSignedEncryptedResponse);
        when(dcsCryptographyService.preparePayload(any(PassportAttributes.class)))
                .thenReturn(jwsObject);
        when(dcsCryptographyService.unwrapDcsResponse(any(DcsSignedEncryptedResponse.class)))
                .thenReturn(invalidDcsResponse);
        when(authorizationCodeService.generateAuthorizationCode()).thenReturn(authorizationCode);
        when(authRequestValidator.validateRequest(anyMap())).thenReturn(Optional.empty());

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
                persistedPassportCheckDao.getValue().getAttributes().getPassportNumber());
        assertEquals(
                INVALID_GPG45_SCORE.getStrength(),
                persistedPassportCheckDao.getValue().getGpg45Score().getStrength());
        assertEquals(
                INVALID_GPG45_SCORE.getValidity(),
                persistedPassportCheckDao.getValue().getGpg45Score().getValidity());
        assertEquals(
                invalidDcsResponse,
                persistedPassportCheckDao.getValue().getAttributes().getDcsResponse());
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
        when(dcsCryptographyService.preparePayload(any(PassportAttributes.class)))
                .thenReturn(jwsObject);
        when(dcsCryptographyService.unwrapDcsResponse(any(DcsSignedEncryptedResponse.class)))
                .thenReturn(validDcsResponse);
        when(authorizationCodeService.generateAuthorizationCode()).thenReturn(authorizationCode);
        when(authRequestValidator.validateRequest(anyMap())).thenReturn(Optional.empty());

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
        ArgumentCaptor<String> redirectUrlArgumentCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<PassportCheckDao> dcsResponseItemArgumentCaptor =
                ArgumentCaptor.forClass(PassportCheckDao.class);
        verify(passportService).persistDcsResponse(dcsResponseItemArgumentCaptor.capture());

        verify(authorizationCodeService)
                .persistAuthorizationCode(
                        authCodeArgumentCaptor.capture(),
                        resourceIdArgumentCaptor.capture(),
                        redirectUrlArgumentCaptor.capture());

        assertEquals(authorizationCode.toString(), authCodeArgumentCaptor.getValue());
        assertEquals(
                dcsResponseItemArgumentCaptor.getValue().getResourceId(),
                resourceIdArgumentCaptor.getValue());
        assertEquals(
                params.get(OAuth2RequestParams.REDIRECT_URI), redirectUrlArgumentCaptor.getValue());
    }

    @Test
    void shouldReturn400IfCanNotParseAuthRequestFromQueryStringParams()
            throws JsonProcessingException {
        when(authRequestValidator.validateRequest(anyMap())).thenReturn(Optional.empty());

        List<String> paramsToRemove =
                List.of(
                        OAuth2RequestParams.REDIRECT_URI,
                        OAuth2RequestParams.CLIENT_ID,
                        OAuth2RequestParams.RESPONSE_TYPE,
                        OAuth2RequestParams.SCOPE);
        for (String param : paramsToRemove) {
            Map<String, String> unparseableParams = new HashMap<>(VALID_QUERY_PARAMS);
            unparseableParams.remove(param);

            APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
            event.setQueryStringParameters(unparseableParams);
            event.setHeaders(TEST_EVENT_HEADERS);

            APIGatewayProxyResponseEvent response = underTest.handleRequest(event, context);

            Map<String, Object> responseBody =
                    objectMapper.readValue(response.getBody(), new TypeReference<>() {});
            assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
            assertEquals(
                    ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS.getCode(),
                    responseBody.get("code"));
            assertEquals(
                    ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS.getMessage(),
                    responseBody.get("message"));
            verify(authorizationCodeService, never())
                    .persistAuthorizationCode(anyString(), anyString(), anyString());
        }
    }
}
