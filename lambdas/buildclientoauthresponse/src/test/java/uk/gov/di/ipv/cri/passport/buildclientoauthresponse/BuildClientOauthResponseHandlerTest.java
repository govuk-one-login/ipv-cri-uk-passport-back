package uk.gov.di.ipv.cri.passport.buildclientoauthresponse;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.apache.http.HttpStatus;
import org.apache.http.client.utils.URIBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.common.library.persistence.item.SessionItem;
import uk.gov.di.ipv.cri.passport.buildclientoauthresponse.domain.ClientResponse;
import uk.gov.di.ipv.cri.passport.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.cri.passport.library.auditing.AuditEventUser;
import uk.gov.di.ipv.cri.passport.library.config.ConfigurationService;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.library.exceptions.SqsException;
import uk.gov.di.ipv.cri.passport.library.service.AuditService;
import uk.gov.di.ipv.cri.passport.library.service.AuthorizationCodeService;
import uk.gov.di.ipv.cri.passport.library.service.PassportSessionService;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class BuildClientOauthResponseHandlerTest {
    private static final String PASSPORT_SESSION_ID_HEADER_NAME = "passport_session_id";
    private static final Map<String, String> TEST_EVENT_HEADERS =
            Map.of(PASSPORT_SESSION_ID_HEADER_NAME, "12345");
    public static final String TEST_USER_ID = "test-user-id";
    public static final String TEST_GOVUK_SIGNIN_JOURNEY_ID = "test-govuk-signin-journey-id";
    public static final String TEST_PASSPORT_SESSION_ID = "test-passport-session-id";

    @Mock private Context context;
    @Mock private AuthorizationCodeService mockAuthorizationCodeService;
    @Mock private PassportSessionService mockPassportSessionService;
    @Mock private ConfigurationService mockConfigurationService;
    @Mock private AuditService mockAuditService;

    private AuthorizationCode authorizationCode;
    private BuildClientOauthResponseHandler handler;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setUp() {
        authorizationCode = new AuthorizationCode();
        handler =
                new BuildClientOauthResponseHandler(
                        mockAuthorizationCodeService,
                        mockPassportSessionService,
                        mockAuditService,
                        mockConfigurationService);
    }

    @Test
    void shouldReturn200OnSuccessfulRequest()
            throws JsonProcessingException, SqsException, URISyntaxException {
        when(mockAuthorizationCodeService.generateAuthorizationCode())
                .thenReturn(authorizationCode);
        SessionItem sessionItem = generatePassportSessionItem();
        when(mockPassportSessionService.getPassportSession(anyString()))
                .thenReturn(sessionItem);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        event.setHeaders(TEST_EVENT_HEADERS);

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        ClientResponse responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        verify(mockAuthorizationCodeService)
                .persistAuthorizationCode(
                        eq(authorizationCode.getValue()),
                        any(SessionItem.class));

        verify(mockAuditService)
                .sendAuditEvent(
                        AuditEventTypes.IPV_PASSPORT_CRI_END,
                        new AuditEventUser(
                                TEST_USER_ID,
                                sessionItem.getSessionId().toString(),
                                TEST_GOVUK_SIGNIN_JOURNEY_ID));

        String expectedRedirectUrl =
                new URIBuilder("https://example.com")
                        .addParameter("code", authorizationCode.toString())
                        .addParameter("state", "test-state")
                        .build()
                        .toString();

        assertEquals(expectedRedirectUrl, responseBody.getClient().getRedirectUrl());
    }

    @Test
    void shouldReturn200WhenStateNotInSession() throws Exception {
        when(mockAuthorizationCodeService.generateAuthorizationCode())
                .thenReturn(authorizationCode);

        SessionItem passportSessionItem = generatePassportSessionItem();
        passportSessionItem.setState(null);
        when(mockPassportSessionService.getPassportSession(anyString()))
                .thenReturn(passportSessionItem);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(TEST_EVENT_HEADERS);

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        ClientResponse responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        String expectedRedirectUrl =
                new URIBuilder("https://example.com")
                        .addParameter("code", authorizationCode.toString())
                        .build()
                        .toString();

        assertEquals(expectedRedirectUrl, responseBody.getClient().getRedirectUrl());
    }

    @Test
    void shouldReturn400WhenPassportSessionIdHeaderIsMissing() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(
                ErrorResponse.MISSING_PASSPORT_SESSION_ID_HEADER.getCode(),
                responseBody.get("code"));
        assertEquals(
                ErrorResponse.MISSING_PASSPORT_SESSION_ID_HEADER.getMessage(),
                responseBody.get("message"));
    }

    @Test
    void shouldReturn500IfAuditServiceFails() throws SqsException, JsonProcessingException {
        when(mockAuthorizationCodeService.generateAuthorizationCode())
                .thenReturn(authorizationCode);
        when(mockPassportSessionService.getPassportSession(anyString()))
                .thenReturn(generatePassportSessionItem());
        doThrow(new SqsException("Test error"))
                .when(mockAuditService)
                .sendAuditEvent(
                        eq(AuditEventTypes.IPV_PASSPORT_CRI_END), any(AuditEventUser.class));

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        event.setHeaders(TEST_EVENT_HEADERS);

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(OAuth2Error.SERVER_ERROR.getCode(), responseBody.get("error"));
        assertEquals("Test error", responseBody.get("error_description"));
    }

    @Test
    void shouldReturnAccessDeniedResponseIfNoPassportAttemptHasBeenMade()
            throws JsonProcessingException, SqsException, URISyntaxException {
        SessionItem passportSessionItem = generatePassportSessionItem();
        passportSessionItem.setAttemptCount(0);
        when(mockPassportSessionService.getPassportSession(anyString()))
                .thenReturn(passportSessionItem);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        event.setHeaders(TEST_EVENT_HEADERS);

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());

        ClientResponse responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        String expectedRedirectUrl =
                new URIBuilder("https://example.com")
                        .addParameter("error", OAuth2Error.ACCESS_DENIED.getCode())
                        .addParameter(
                                "error_description", OAuth2Error.ACCESS_DENIED.getDescription())
                        .addParameter("state", "test-state")
                        .build()
                        .toString();

        assertEquals(expectedRedirectUrl, responseBody.getClient().getRedirectUrl());
    }

    private SessionItem generatePassportSessionItem() {
        SessionItem item = new SessionItem();

        item.setAccessToken("code");
        item.setRedirectUri(URI.create( "https://example.com"));
        item.setState("test-state");
        item.setSessionId(item.getSessionId());
        item.setClientId(TEST_GOVUK_SIGNIN_JOURNEY_ID);
        item.setCreatedDate(Instant.now().getEpochSecond());
        item.setSubject(TEST_USER_ID);
        item.setAttemptCount(1);
        item.setClientSessionId("test-govuk-signin-journey-id");

        return item;
    }
}
