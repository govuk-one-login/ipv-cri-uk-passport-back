package uk.gov.di.ipv.cri.passport.checkpassport;

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
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.apache.http.HttpStatus;
import org.apache.http.client.utils.URIBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.common.library.domain.AuditEventContext;
import uk.gov.di.ipv.cri.common.library.domain.AuditEventType;
import uk.gov.di.ipv.cri.common.library.exception.SqsException;
import uk.gov.di.ipv.cri.common.library.persistence.item.SessionItem;
import uk.gov.di.ipv.cri.common.library.service.AuditService;
import uk.gov.di.ipv.cri.common.library.service.SessionService;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.ClientResponse;
import uk.gov.di.ipv.cri.passport.library.config.PassportConfigurationService;
import uk.gov.di.ipv.cri.passport.library.domain.DcsPayload;
import uk.gov.di.ipv.cri.passport.library.domain.DcsResponse;
import uk.gov.di.ipv.cri.passport.library.domain.DcsSignedEncryptedResponse;
import uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.Evidence;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.library.exceptions.EmptyDcsResponseException;
import uk.gov.di.ipv.cri.passport.library.persistence.item.PassportCheckDao;
import uk.gov.di.ipv.cri.passport.library.service.AuthorizationCodeService;
import uk.gov.di.ipv.cri.passport.library.service.DcsCryptographyService;
import uk.gov.di.ipv.cri.passport.library.service.PassportService;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.cri.passport.library.config.ConfigurationVariable.MAXIMUM_ATTEMPT_COUNT;

@ExtendWith(MockitoExtension.class)
class CheckPassportHandlerTest {
    private static final String PASSPORT_SESSION_ID_HEADER_NAME = "session_id";
    public static final String PASSPORT_SESSION_ID = UUID.randomUUID().toString();
    public static final UUID TEST_PASSPORT_SESSION_ID = UUID.randomUUID();
    public static final String TEST_USER_ID = "test-user-id";
    public static final String TEST_GOVUK_SIGNIN_JOURNEY_ID = "test-govuk-signin-journey-id";
    private static final Map<String, String> TEST_EVENT_HEADERS =
            Map.of(PASSPORT_SESSION_ID_HEADER_NAME, PASSPORT_SESSION_ID, "user_id", TEST_USER_ID);
    public static final String PASSPORT_NUMBER = "1234567890";
    public static final String SURNAME = "Tattsyrup";
    public static final List<String> FORENAMES = List.of("Tubbs");
    public static final String DATE_OF_BIRTH = "1984-09-28";
    public static final String EXPIRY_DATE = "2024-09-03";
    public static final Evidence VALID_PASSPORT_EVIDENCE =
            new Evidence(UUID.randomUUID().toString(), 4, 2, null);

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
    @Mock PassportConfigurationService mockPassportConfigurationService;
    @Mock DcsCryptographyService dcsCryptographyService;
    @Mock AuthorizationCodeService mockAuthorizationCodeService;
    @Mock SessionService mockSessionService;
    @Mock AuditService mockAuditService;
    @Mock JWSObject jwsObject;

    private AuthorizationCode authorizationCode;

    private CheckPassportHandler checkPassportHandler;

    @BeforeEach
    void setUp() {
        authorizationCode = new AuthorizationCode();
        checkPassportHandler =
                new CheckPassportHandler(
                        passportService,
                        mockPassportConfigurationService,
                        dcsCryptographyService,
                        mockAuditService,
                        mockSessionService);
    }

    @Test
    void shouldReturn200WithCorrectFormData()
            throws IOException, CertificateException, NoSuchAlgorithmException,
                    InvalidKeySpecException, JOSEException, ParseException,
                    EmptyDcsResponseException, SqsException {
        mockSessionItem(0);
        mockDcsResponse(validDcsResponse);

        APIGatewayProxyRequestEvent mockRequestEvent =
                Mockito.mock(APIGatewayProxyRequestEvent.class);

        when(mockRequestEvent.getBody())
                .thenReturn(objectMapper.writeValueAsString(validPassportFormData));
        Map<String, String> requestHeaders =
                Map.of("session_id", TEST_PASSPORT_SESSION_ID.toString());
        when(mockRequestEvent.getHeaders()).thenReturn(requestHeaders);

        when(context.getFunctionName()).thenReturn("functionName");
        when(context.getFunctionVersion()).thenReturn("1.0");
        APIGatewayProxyResponseEvent responseEvent =
                checkPassportHandler.handleRequest(mockRequestEvent, context);

        verify(mockAuditService, times(1))
                .sendAuditEvent(eq(AuditEventType.REQUEST_SENT), any(AuditEventContext.class));
        verify(mockAuditService, times(1))
                .sendAuditEvent(
                        eq(AuditEventType.THIRD_PARTY_REQUEST_ENDED),
                        any(AuditEventContext.class),
                        eq(null));

        assertEquals(HttpStatus.SC_OK, responseEvent.getStatusCode());
    }

    @Test
    void shouldPersistPassportCheckDao()
            throws IOException, CertificateException, NoSuchAlgorithmException,
                    InvalidKeySpecException, JOSEException, ParseException,
                    EmptyDcsResponseException {
        mockSessionItem(0);
        mockDcsResponse(validDcsResponse);

        APIGatewayProxyRequestEvent mockRequestEvent =
                Mockito.mock(APIGatewayProxyRequestEvent.class);

        when(mockRequestEvent.getBody())
                .thenReturn(objectMapper.writeValueAsString(validPassportFormData));
        Map<String, String> requestHeaders =
                Map.of("session_id", TEST_PASSPORT_SESSION_ID.toString());
        when(mockRequestEvent.getHeaders()).thenReturn(requestHeaders);

        when(context.getFunctionName()).thenReturn("functionName");
        when(context.getFunctionVersion()).thenReturn("1.0");
        APIGatewayProxyResponseEvent responseEvent =
                checkPassportHandler.handleRequest(mockRequestEvent, context);

        ArgumentCaptor<PassportCheckDao> persistedPassportCheckDao =
                ArgumentCaptor.forClass(PassportCheckDao.class);

        verify(passportService).persistDcsResponse(persistedPassportCheckDao.capture());
        assertEquals(
                validPassportFormData.get("passportNumber"),
                persistedPassportCheckDao.getValue().getDcsPayload().getPassportNumber());
        assertEquals(
                VALID_PASSPORT_EVIDENCE.getStrengthScore(),
                persistedPassportCheckDao.getValue().getEvidence().getStrengthScore());
        assertEquals(
                VALID_PASSPORT_EVIDENCE.getValidityScore(),
                persistedPassportCheckDao.getValue().getEvidence().getValidityScore());
        assertNull(persistedPassportCheckDao.getValue().getEvidence().getCi());
    }

    @Test
    void shouldReturn200OnValidDCSResponseAndBelowAttemptCountLimit()
            throws IOException, CertificateException, NoSuchAlgorithmException,
                    InvalidKeySpecException, JOSEException, ParseException,
                    EmptyDcsResponseException, SqsException, URISyntaxException {
        SessionItem sessionItem = mockSessionItem(0);
        mockDcsResponse(validDcsResponse);

        APIGatewayProxyRequestEvent mockRequestEvent =
                Mockito.mock(APIGatewayProxyRequestEvent.class);

        when(mockRequestEvent.getBody())
                .thenReturn(objectMapper.writeValueAsString(validPassportFormData));
        Map<String, String> requestHeaders =
                Map.of("session_id", TEST_PASSPORT_SESSION_ID.toString());
        when(mockRequestEvent.getHeaders()).thenReturn(requestHeaders);

        when(context.getFunctionName()).thenReturn("functionName");
        when(context.getFunctionVersion()).thenReturn("1.0");
        APIGatewayProxyResponseEvent responseEvent =
                checkPassportHandler.handleRequest(mockRequestEvent, context);

        ClientResponse responseBody =
                objectMapper.readValue(responseEvent.getBody(), new TypeReference<>() {});

        verify(mockAuditService, times(1))
                .sendAuditEvent(eq(AuditEventType.REQUEST_SENT), any(AuditEventContext.class));
        verify(mockAuditService, times(1))
                .sendAuditEvent(
                        eq(AuditEventType.THIRD_PARTY_REQUEST_ENDED),
                        any(AuditEventContext.class),
                        eq(null));

        String expectedRedirectUrl =
                new URIBuilder("https://example.com")
                        .addParameter("code", sessionItem.getAuthorizationCode())
                        .addParameter("state", sessionItem.getState())
                        .build()
                        .toString();

        assertEquals(expectedRedirectUrl, responseBody.getClient().getRedirectUrl());
        assertEquals(HttpStatus.SC_OK, responseEvent.getStatusCode());
    }

    @Test
    void shouldReturnRetryOnInvalidDCSResponseAndBelowAttemptCountLimit()
            throws IOException, CertificateException, NoSuchAlgorithmException,
                    InvalidKeySpecException, JOSEException, ParseException,
                    EmptyDcsResponseException {
        mockSessionItem(0);
        mockDcsResponse(invalidDcsResponse);
        when(mockPassportConfigurationService.getStackSsmParameter(MAXIMUM_ATTEMPT_COUNT))
                .thenReturn(String.valueOf(2));

        APIGatewayProxyRequestEvent event =
                getApiGatewayProxyRequestEvent(
                        "test-client-id", objectMapper.writeValueAsString(validPassportFormData));

        when(context.getFunctionName()).thenReturn("functionName");
        when(context.getFunctionVersion()).thenReturn("1.0");
        Map<String, Object> responseBody =
                getResponseBody(checkPassportHandler.handleRequest(event, context));
        assertEquals("retry", responseBody.get("result"));
    }

    @Test
    void shouldReturn200OnInvalidDCSResponseAndAttemptCountLimitReached()
            throws IOException, CertificateException, NoSuchAlgorithmException,
                    InvalidKeySpecException, JOSEException, ParseException,
                    EmptyDcsResponseException {
        mockSessionItem(2);
        mockDcsResponse(invalidDcsResponse);
        when(mockPassportConfigurationService.getStackSsmParameter(MAXIMUM_ATTEMPT_COUNT))
                .thenReturn(String.valueOf(2));

        APIGatewayProxyRequestEvent event =
                getApiGatewayProxyRequestEvent(
                        "test-client-id", objectMapper.writeValueAsString(validPassportFormData));

        var response = checkPassportHandler.handleRequest(event, context);
        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldReturn400IfPassportSessionIdMissing() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(new HashMap<>());
        Map<String, String> missingSessionHeaders = new HashMap<>(TEST_EVENT_HEADERS);
        missingSessionHeaders.remove(PASSPORT_SESSION_ID_HEADER_NAME);
        event.setHeaders(missingSessionHeaders);

        Map<String, Object> responseBody =
                getResponseBody(checkPassportHandler.handleRequest(event, context));

        System.out.println(responseBody.toString());

        assertEquals(
                ErrorResponse.MISSING_PASSPORT_SESSION_ID_HEADER.getCode(),
                responseBody.get("code"));
        assertEquals(
                ErrorResponse.MISSING_PASSPORT_SESSION_ID_HEADER.getMessage(),
                responseBody.get("message"));
    }

    @Test
    void shouldReturn400IfPassportSessionItemIsNotFound() throws Exception {
        when(mockSessionService.validateSessionId(PASSPORT_SESSION_ID)).thenReturn(null);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(new HashMap<>());
        Map<String, String> missingSessionHeaders = new HashMap<>(TEST_EVENT_HEADERS);
        event.setHeaders(missingSessionHeaders);

        Map<String, Object> responseBody =
                getResponseBody(checkPassportHandler.handleRequest(event, context));

        assertEquals(
                ErrorResponse.PASSPORT_SESSION_NOT_FOUND.getMessage(),
                responseBody.get("error_description"));
    }

    @Test
    void shouldReturn400OAuthErrorIfDataIsMissing() throws JsonProcessingException {
        mockSessionItem(0);
        var formFields = validPassportFormData.keySet();
        for (String keyToRemove : formFields) {
            APIGatewayProxyRequestEvent event =
                    getApiGatewayProxyRequestEvent(
                            "12345",
                            objectMapper.writeValueAsString(
                                    new HashMap<>(validPassportFormData).remove(keyToRemove)));

            var response = checkPassportHandler.handleRequest(event, context);
            var responseBody = getResponseBody(response);

            assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
            assertEquals(OAuth2Error.SERVER_ERROR_CODE, responseBody.get("error"));
            assertEquals(
                    ErrorResponse.FAILED_TO_PARSE_PASSPORT_FORM_DATA.getMessage(),
                    responseBody.get("error_description"));
        }
    }

    @Test
    void shouldReturn400OAuthErrorIfDateStringsAreWrongFormat() throws JsonProcessingException {
        mockSessionItem(2);

        var mangledDateInput = new HashMap<>(validPassportFormData);
        mangledDateInput.put("dateOfBirth", "28-09-1984");

        APIGatewayProxyRequestEvent event =
                getApiGatewayProxyRequestEvent(
                        "12345", objectMapper.writeValueAsString(mangledDateInput));

        var response = checkPassportHandler.handleRequest(event, context);
        var responseBody = getResponseBody(response);

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(OAuth2Error.SERVER_ERROR_CODE, responseBody.get("error"));
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_PASSPORT_FORM_DATA.getMessage(),
                responseBody.get("error_description"));
    }

    @Test
    void shouldReturn500OAuthErrorOnDcsErrorResponse() throws Exception {
        DcsSignedEncryptedResponse dcsSignedEncryptedResponse =
                new DcsSignedEncryptedResponse("TEST_PAYLOAD");
        when(passportService.dcsPassportCheck(any(JWSObject.class)))
                .thenReturn(dcsSignedEncryptedResponse);
        when(dcsCryptographyService.preparePayload(any(DcsPayload.class))).thenReturn(jwsObject);

        DcsResponse errorDcsResponse =
                new DcsResponse(
                        UUID.randomUUID().toString(),
                        UUID.randomUUID().toString(),
                        true,
                        false,
                        List.of("Test DCS error message"));
        when(dcsCryptographyService.unwrapDcsResponse(any(DcsSignedEncryptedResponse.class)))
                .thenReturn(errorDcsResponse);

        mockSessionItem(0);

        APIGatewayProxyRequestEvent event =
                getApiGatewayProxyRequestEvent(
                        "12345", objectMapper.writeValueAsString(validPassportFormData));

        var response = checkPassportHandler.handleRequest(event, context);
        var responseBody = getResponseBody(response);

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals(OAuth2Error.SERVER_ERROR_CODE, responseBody.get("error"));
        assertEquals(
                ErrorResponse.DCS_RETURNED_AN_ERROR.getMessage(),
                responseBody.get("error_description"));
    }

    private APIGatewayProxyRequestEvent getApiGatewayProxyRequestEvent(
            String clientId, String body) {
        var event = new APIGatewayProxyRequestEvent();
        Map<String, String> params = new HashMap<>();
        params.put(OAuth2RequestParams.REDIRECT_URI, "https://example.com");
        params.put(OAuth2RequestParams.CLIENT_ID, clientId);
        params.put(OAuth2RequestParams.RESPONSE_TYPE, "code");
        params.put(OAuth2RequestParams.SCOPE, "openid");
        event.setQueryStringParameters(params);
        event.setHeaders(TEST_EVENT_HEADERS);
        event.setBody(body);
        return event;
    }

    private Map<String, Object> getResponseBody(APIGatewayProxyResponseEvent response)
            throws JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.readValue(response.getBody(), new TypeReference<>() {});
    }

    private void mockDcsResponse(DcsResponse validDcsResponse)
            throws IOException, EmptyDcsResponseException, CertificateException,
                    NoSuchAlgorithmException, InvalidKeySpecException, JOSEException,
                    ParseException {
        DcsSignedEncryptedResponse dcsSignedEncryptedResponse =
                new DcsSignedEncryptedResponse("TEST_PAYLOAD");
        when(passportService.dcsPassportCheck(any(JWSObject.class)))
                .thenReturn(dcsSignedEncryptedResponse);
        when(dcsCryptographyService.preparePayload(any(DcsPayload.class))).thenReturn(jwsObject);
        when(dcsCryptographyService.unwrapDcsResponse(any(DcsSignedEncryptedResponse.class)))
                .thenReturn(validDcsResponse);
    }

    private SessionItem mockSessionItem(int attemptCount) {
        SessionItem sessionItem = new SessionItem();
        sessionItem.setAttemptCount(attemptCount);
        sessionItem.setUserId(TEST_USER_ID);
        sessionItem.setSessionId(TEST_PASSPORT_SESSION_ID);
        sessionItem.setClientSessionId(TEST_GOVUK_SIGNIN_JOURNEY_ID);
        sessionItem.setAuthorizationCode("12345");
        sessionItem.setState("test-state");
        sessionItem.setRedirectUri(URI.create("https://example.com"));

        when(mockSessionService.validateSessionId(anyString())).thenReturn(sessionItem);
        return sessionItem;
    }
}
