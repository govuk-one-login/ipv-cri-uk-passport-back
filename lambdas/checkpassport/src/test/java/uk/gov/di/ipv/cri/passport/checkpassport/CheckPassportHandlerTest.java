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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.passport.checkpassport.validation.AuthRequestValidator;
import uk.gov.di.ipv.cri.passport.library.auditing.AuditEvent;
import uk.gov.di.ipv.cri.passport.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.cri.passport.library.domain.DcsPayload;
import uk.gov.di.ipv.cri.passport.library.domain.DcsResponse;
import uk.gov.di.ipv.cri.passport.library.domain.DcsSignedEncryptedResponse;
import uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.ContraIndicators;
import uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.Evidence;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.library.exceptions.EmptyDcsResponseException;
import uk.gov.di.ipv.cri.passport.library.exceptions.SqsException;
import uk.gov.di.ipv.cri.passport.library.persistence.item.PassportCheckDao;
import uk.gov.di.ipv.cri.passport.library.persistence.item.PassportSessionItem;
import uk.gov.di.ipv.cri.passport.library.service.AuditService;
import uk.gov.di.ipv.cri.passport.library.service.AuthorizationCodeService;
import uk.gov.di.ipv.cri.passport.library.service.ConfigurationService;
import uk.gov.di.ipv.cri.passport.library.service.DcsCryptographyService;
import uk.gov.di.ipv.cri.passport.library.service.PassportService;
import uk.gov.di.ipv.cri.passport.library.service.PassportSessionService;

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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CheckPassportHandlerTest {
    public static final String PASSPORT_SESSION_ID = "test-passport-session-id";
    private static final Map<String, String> TEST_EVENT_HEADERS =
            Map.of("passport_session_id", PASSPORT_SESSION_ID, "user_id", "test-user-id");
    public static final String PASSPORT_NUMBER = "1234567890";
    public static final String SURNAME = "Tattsyrup";
    public static final List<String> FORENAMES = List.of("Tubbs");
    public static final String DATE_OF_BIRTH = "1984-09-28";
    public static final String EXPIRY_DATE = "2024-09-03";
    public static final Evidence VALID_PASSPORT_EVIDENCE =
            new Evidence(UUID.randomUUID().toString(), 4, 2, null);
    public static final Evidence INVALID_PASSPORT_EVIDENCE =
            new Evidence(UUID.randomUUID().toString(), 4, 0, List.of(ContraIndicators.D02));
    public static final String TEST_REDIRECT_URI = "https://example.com";
    private static final Map<String, String> VALID_QUERY_PARAMS =
            Map.of(
                    OAuth2RequestParams.REDIRECT_URI, TEST_REDIRECT_URI,
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
    @Mock PassportSessionService passportSessionService;
    @Mock AuditService auditService;
    @Mock AuthRequestValidator authRequestValidator;
    @Mock JWSObject jwsObject;

    private CheckPassportHandler underTest;
    private AuthorizationCode authorizationCode;

    @BeforeEach
    void setUp() {
        authorizationCode = new AuthorizationCode();
        underTest =
                new CheckPassportHandler(
                        passportService,
                        authorizationCodeService,
                        configurationService,
                        dcsCryptographyService,
                        auditService,
                        authRequestValidator,
                        passportSessionService);
    }

    @Test
    void shouldReturn200WithCorrectFormData()
            throws IOException, CertificateException, NoSuchAlgorithmException,
                    InvalidKeySpecException, JOSEException, ParseException,
                    EmptyDcsResponseException, SqsException {
        mockDcsResponse(validDcsResponse);
        mockPassportSessionItem(0);

        APIGatewayProxyRequestEvent event =
                getApiGatewayProxyRequestEvent(
                        "12345", objectMapper.writeValueAsString(validPassportFormData));

        var response = underTest.handleRequest(event, context);

        ArgumentCaptor<AuditEvent> argumentCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditService, times(2)).sendAuditEvent(argumentCaptor.capture());
        List<AuditEvent> capturedValues = argumentCaptor.getAllValues();
        assertEquals(
                AuditEventTypes.IPV_PASSPORT_CRI_REQUEST_SENT,
                capturedValues.get(0).getEventName());
        assertEquals(
                AuditEventTypes.IPV_PASSPORT_CRI_RESPONSE_RECEIVED,
                capturedValues.get(1).getEventName());

        verify(auditService).sendAuditEvent(AuditEventTypes.IPV_PASSPORT_CRI_END);
        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldPersistPassportCheckDao()
            throws IOException, CertificateException, NoSuchAlgorithmException,
                    InvalidKeySpecException, JOSEException, ParseException,
                    EmptyDcsResponseException {
        mockDcsResponse(validDcsResponse);
        mockPassportSessionItem(0);

        APIGatewayProxyRequestEvent event =
                getApiGatewayProxyRequestEvent(
                        "12345", objectMapper.writeValueAsString(validPassportFormData));

        underTest.handleRequest(event, context);

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
    void shouldPersistAndReturnAuthorizationCode()
            throws CertificateException, IOException, NoSuchAlgorithmException,
                    InvalidKeySpecException, ParseException, EmptyDcsResponseException,
                    JOSEException {
        mockDcsResponse(validDcsResponse);
        mockPassportSessionItem(0);

        APIGatewayProxyRequestEvent event =
                getApiGatewayProxyRequestEvent(
                        "12345", objectMapper.writeValueAsString(validPassportFormData));

        Map<String, Object> responseBody = getResponseBody(underTest.handleRequest(event, context));

        Map<String, String> authCode = (Map<String, String>) responseBody.get("code");
        verify(authorizationCodeService)
                .persistAuthorizationCode(
                        eq(authorizationCode.toString()),
                        anyString(),
                        eq(TEST_REDIRECT_URI),
                        eq(PASSPORT_SESSION_ID));
        assertEquals(authorizationCode.toString(), authCode.get("value"));
    }

    @Test
    void shouldReturnFinishOnValidDCSResponseAndBelowAttemptCountLimit()
            throws IOException, CertificateException, NoSuchAlgorithmException,
                    InvalidKeySpecException, JOSEException, ParseException,
                    EmptyDcsResponseException {
        mockDcsResponse(validDcsResponse);
        mockPassportSessionItem(0);

        APIGatewayProxyRequestEvent event =
                getApiGatewayProxyRequestEvent(
                        "test-client-id", objectMapper.writeValueAsString(validPassportFormData));

        Map<String, Object> responseBody = getResponseBody(underTest.handleRequest(event, context));
        assertEquals("finish", responseBody.get("result"));
    }

    @Test
    void shouldReturnRetryOnInvalidDCSResponseAndBelowAttemptCountLimit()
            throws IOException, CertificateException, NoSuchAlgorithmException,
                    InvalidKeySpecException, JOSEException, ParseException,
                    EmptyDcsResponseException {
        mockDcsResponse(invalidDcsResponse);
        mockPassportSessionItem(0);
        when(configurationService.getMaximumAttemptCount()).thenReturn(2);

        APIGatewayProxyRequestEvent event =
                getApiGatewayProxyRequestEvent(
                        "test-client-id", objectMapper.writeValueAsString(validPassportFormData));

        Map<String, Object> responseBody = getResponseBody(underTest.handleRequest(event, context));
        assertEquals("retry", responseBody.get("result"));
    }

    @Test
    void shouldReturnFinishOnInvalidDCSResponseAndAttemptCountLimitReached()
            throws IOException, CertificateException, NoSuchAlgorithmException,
                    InvalidKeySpecException, JOSEException, ParseException,
                    EmptyDcsResponseException {
        mockDcsResponse(invalidDcsResponse);
        mockPassportSessionItem(2);
        when(configurationService.getMaximumAttemptCount()).thenReturn(2);

        APIGatewayProxyRequestEvent event =
                getApiGatewayProxyRequestEvent(
                        "test-client-id", objectMapper.writeValueAsString(validPassportFormData));

        Map<String, Object> responseBody = getResponseBody(underTest.handleRequest(event, context));
        assertEquals("finish", responseBody.get("result"));
    }

    @Test
    void shouldReturn400IfPassportSessionIdMissing() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(new HashMap<>());
        Map<String, String> missingSessionHeaders = new HashMap<>(TEST_EVENT_HEADERS);
        missingSessionHeaders.remove("passport_session_id");
        event.setHeaders(missingSessionHeaders);

        Map<String, Object> responseBody = getResponseBody(underTest.handleRequest(event, context));

        assertEquals(
                ErrorResponse.MISSING_PASSPORT_SESSION_ID_HEADER.getCode(),
                responseBody.get("code"));
        assertEquals(
                ErrorResponse.MISSING_PASSPORT_SESSION_ID_HEADER.getMessage(),
                responseBody.get("message"));
    }

    @Test
    void shouldReturn400OAuthErrorIfRequestFailsValidation() throws Exception {
        when(authRequestValidator.validateRequest(anyMap(), any()))
                .thenReturn(Optional.of(ErrorResponse.MISSING_QUERY_PARAMETERS));

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(new HashMap<>());
        event.setHeaders(TEST_EVENT_HEADERS);
        event.setBody(objectMapper.writeValueAsString(validPassportFormData));

        Map<String, Object> responseBody = getResponseBody(underTest.handleRequest(event, context));
        assertEquals(OAuth2Error.SERVER_ERROR_CODE, responseBody.get("error"));
        assertEquals(
                ErrorResponse.MISSING_QUERY_PARAMETERS.getMessage(),
                responseBody.get("error_description"));
    }

    @Test
    void shouldReturn400OAuthErrorIfDataIsMissing() throws JsonProcessingException {
        when(authRequestValidator.validateRequest(anyMap(), anyString()))
                .thenReturn(Optional.empty());
        var formFields = validPassportFormData.keySet();
        for (String keyToRemove : formFields) {
            APIGatewayProxyRequestEvent event =
                    getApiGatewayProxyRequestEvent(
                            "12345",
                            objectMapper.writeValueAsString(
                                    new HashMap<>(validPassportFormData).remove(keyToRemove)));

            var response = underTest.handleRequest(event, context);
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
        when(authRequestValidator.validateRequest(anyMap(), anyString()))
                .thenReturn(Optional.empty());

        var mangledDateInput = new HashMap<>(validPassportFormData);
        mangledDateInput.put("dateOfBirth", "28-09-1984");

        APIGatewayProxyRequestEvent event =
                getApiGatewayProxyRequestEvent(
                        "12345", objectMapper.writeValueAsString(mangledDateInput));

        var response = underTest.handleRequest(event, context);
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
        when(authRequestValidator.validateRequest(anyMap(), anyString()))
                .thenReturn(Optional.empty());

        DcsResponse errorDcsResponse =
                new DcsResponse(
                        UUID.randomUUID().toString(),
                        UUID.randomUUID().toString(),
                        true,
                        false,
                        List.of("Test DCS error message"));
        when(dcsCryptographyService.unwrapDcsResponse(any(DcsSignedEncryptedResponse.class)))
                .thenReturn(errorDcsResponse);

        APIGatewayProxyRequestEvent event =
                getApiGatewayProxyRequestEvent(
                        "12345", objectMapper.writeValueAsString(validPassportFormData));

        var response = underTest.handleRequest(event, context);
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

    @Test
    void shouldReturn400OAuthErrorIfCanNotParseAuthRequestFromQueryStringParams()
            throws JsonProcessingException {
        when(authRequestValidator.validateRequest(anyMap(), anyString()))
                .thenReturn(Optional.empty());

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

            Map<String, Object> responseBody = getResponseBody(response);
            assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
            assertEquals(OAuth2Error.SERVER_ERROR_CODE, responseBody.get("error"));
            assertEquals(
                    ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS.getMessage(),
                    responseBody.get("error_description"));
        }
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
        when(authRequestValidator.validateRequest(any(), anyString())).thenReturn(Optional.empty());
        when(authorizationCodeService.generateAuthorizationCode()).thenReturn(authorizationCode);
    }

    private void mockPassportSessionItem(int attemptCount) {
        PassportSessionItem passportSessionItem = new PassportSessionItem();
        passportSessionItem.setAttemptCount(attemptCount);
        when(passportSessionService.getPassportSession(PASSPORT_SESSION_ID))
                .thenReturn(passportSessionItem);
    }
}
