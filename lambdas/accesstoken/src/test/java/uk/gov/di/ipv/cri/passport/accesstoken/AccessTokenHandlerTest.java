package uk.gov.di.ipv.cri.passport.accesstoken;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import org.apache.http.HttpStatus;
import org.aspectj.lang.annotation.Before;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.common.library.persistence.item.SessionItem;
import uk.gov.di.ipv.cri.passport.accesstoken.exceptions.ClientAuthenticationException;
import uk.gov.di.ipv.cri.passport.accesstoken.validation.TokenRequestValidator;
import uk.gov.di.ipv.cri.passport.library.service.AccessTokenService;
import uk.gov.di.ipv.cri.passport.library.service.AuthorizationCodeService;
import uk.gov.di.ipv.cri.passport.library.service.PassportSessionService;
import uk.gov.di.ipv.cri.passport.library.validation.ValidationResult;

import java.net.URI;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AccessTokenHandlerTest {

    public static final UUID PASSPORT_SESSION_ID = UUID.randomUUID();
    private static SessionItem TEST_AUTH_CODE_ITEM = new SessionItem();

    private final ObjectMapper objectMapper = new ObjectMapper();
    @Mock private Context context;
    @Mock private AccessTokenService mockAccessTokenService;
    @Mock private AuthorizationCodeService mockAuthorizationCodeService;
    @Mock private PassportSessionService mockPassportSessionService;
    @Mock private TokenRequestValidator mockTokenRequestValidator;
    @InjectMocks private AccessTokenHandler handler;

    @BeforeEach
    public void setup() {
        TEST_AUTH_CODE_ITEM.setAuthorizationCode("12345");
        TEST_AUTH_CODE_ITEM.setRedirectUri(URI.create("http://example.com"));
    }

    @Test
    void shouldReturnAccessTokenOnSuccessfulExchange() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        String tokenRequestBody =
                "code=12345&redirect_uri=http://example.com&grant_type=authorization_code&client_id=test_client_id";
        event.setBody(tokenRequestBody);

        AccessToken accessToken = new BearerAccessToken();
        TokenResponse tokenResponse = new AccessTokenResponse(new Tokens(accessToken, null));
        when(mockAccessTokenService.generateAccessToken()).thenReturn(tokenResponse);

        when(mockAuthorizationCodeService.getSessionByAuthCode("12345")).thenReturn(TEST_AUTH_CODE_ITEM);

        when(mockAccessTokenService.validateAuthorizationGrant(any()))
                .thenReturn(ValidationResult.createValidResult());

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});
        assertEquals(
                ContentType.APPLICATION_JSON.getType(), response.getHeaders().get("Content-Type"));
        assertEquals(200, response.getStatusCode());
        assertEquals(
                tokenResponse.toSuccessResponse().getTokens().getAccessToken().getValue(),
                responseBody.get("access_token").toString());
    }

    @Test
    void shouldReturnAccessTokenWhenNoResourceIdInAuthCode() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        String tokenRequestBody =
                "code=12345&redirect_uri=http://example.com&grant_type=authorization_code&client_id=test_client_id";
        event.setBody(tokenRequestBody);

        AccessToken accessToken = new BearerAccessToken();
        TokenResponse tokenResponse = new AccessTokenResponse(new Tokens(accessToken, null));
        when(mockAccessTokenService.generateAccessToken()).thenReturn(tokenResponse);

        SessionItem authorizationCodeItemWithNoResourceId = new SessionItem();

        authorizationCodeItemWithNoResourceId.setAuthorizationCode(new AuthorizationCode().toString());
        authorizationCodeItemWithNoResourceId.setRedirectUri(URI.create("http://example.com"));
        authorizationCodeItemWithNoResourceId.setCreatedDate(Instant.now().getEpochSecond());
        authorizationCodeItemWithNoResourceId.setSessionId(PASSPORT_SESSION_ID);

        when(mockAuthorizationCodeService.getSessionByAuthCode("12345"))
                .thenReturn(authorizationCodeItemWithNoResourceId);

        when(mockAccessTokenService.validateAuthorizationGrant(any()))
                .thenReturn(ValidationResult.createValidResult());

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});
        assertEquals(200, response.getStatusCode());
        assertEquals(
                tokenResponse.toSuccessResponse().getTokens().getAccessToken().getValue(),
                responseBody.get("access_token").toString());
    }

    @Test
    void shouldReturn400WhenInvalidTokenRequestProvided() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        String invalidTokenRequest = "invalid-token-request";
        event.setBody(invalidTokenRequest);

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        ErrorObject errorResponse = createErrorObjectFromResponse(response.getBody());

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), errorResponse.getCode());
        assertEquals(
                OAuth2Error.INVALID_REQUEST.getDescription() + ": Missing grant_type parameter",
                errorResponse.getDescription());
    }

    @Test
    void shouldReturn400WhenInvalidGrantTypeProvided() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        String tokenRequestBody =
                "code=12345&redirect_uri=http://test.com&grant_type="
                        + GrantType.IMPLICIT.getValue()
                        + "&client_id=test_client_id";

        event.setBody(tokenRequestBody);

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        ErrorObject errorResponse = createErrorObjectFromResponse(response.getBody());

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(OAuth2Error.UNSUPPORTED_GRANT_TYPE.getCode(), errorResponse.getCode());
        assertEquals(
                OAuth2Error.UNSUPPORTED_GRANT_TYPE.getDescription(),
                errorResponse.getDescription());
    }

    @Test
    void shouldReturn400IfAccessTokenServiceDeemsRequestInvalid() throws ParseException {
        when(mockAccessTokenService.validateAuthorizationGrant(any()))
                .thenReturn(new ValidationResult<>(false, OAuth2Error.UNSUPPORTED_GRANT_TYPE));

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        String tokenRequestBody =
                "code=12345&redirect_uri=http://test.com&grant_type=authorization_code&client_id=test_client_id";
        event.setBody(tokenRequestBody);

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        ErrorObject errorResponse = createErrorObjectFromResponse(response.getBody());

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(OAuth2Error.UNSUPPORTED_GRANT_TYPE.getCode(), errorResponse.getCode());
        assertEquals(
                OAuth2Error.UNSUPPORTED_GRANT_TYPE.getDescription(),
                errorResponse.getDescription());
    }

    @Test
    void shouldReturn400OWhenUnknownAuthorisationCodeProvided() throws Exception {
        String tokenRequestBody =
                "code=12345&redirect_uri=http://test.com&grant_type=authorization_code&client_id=test_client_id";
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(tokenRequestBody);

        when(mockAccessTokenService.validateAuthorizationGrant(any()))
                .thenReturn(ValidationResult.createValidResult());

        when(mockAuthorizationCodeService.getSessionByAuthCode("12345")).thenReturn(new SessionItem());

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        ErrorObject errorResponse = createErrorObjectFromResponse(response.getBody());

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(OAuth2Error.INVALID_GRANT.getCode(), errorResponse.getCode());
        assertEquals(OAuth2Error.INVALID_GRANT.getDescription(), errorResponse.getDescription());
    }

    @Test
    void shouldReturn400OWhenAuthorisationCodeHasExpired() throws Exception {
        String tokenRequestBody =
                "code=12345&redirect_uri=http://test.com&grant_type=authorization_code&client_id=test_client_id";
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(tokenRequestBody);

        when(mockAccessTokenService.validateAuthorizationGrant(any()))
                .thenReturn(ValidationResult.createValidResult());

        when(mockAuthorizationCodeService.getSessionByAuthCode("12345")).thenReturn(TEST_AUTH_CODE_ITEM);
        when(mockAuthorizationCodeService.isExpired(TEST_AUTH_CODE_ITEM)).thenReturn(true);

        SessionItem passportSessionItem = new SessionItem();
        passportSessionItem.setClientId(UUID.randomUUID().toString());

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        ErrorObject errorResponse = createErrorObjectFromResponse(response.getBody());

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(OAuth2Error.INVALID_GRANT.getCode(), errorResponse.getCode());
        assertEquals("Authorization code expired", errorResponse.getDescription());
    }

    @Test
    void shouldReturn400WhenInvalidRedirectUriParamIsProvided() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        String tokenRequestBody =
                "code=12345&redirect_uri=http://invalid-uri.com&grant_type=authorization_code&client_id=test_client_id";
        event.setBody(tokenRequestBody);

        when(mockAuthorizationCodeService.getSessionByAuthCode("12345")).thenReturn(TEST_AUTH_CODE_ITEM);

        when(mockAccessTokenService.validateAuthorizationGrant(any()))
                .thenReturn(ValidationResult.createValidResult());
        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        ErrorObject errorResponse = createErrorObjectFromResponse(response.getBody());

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(OAuth2Error.INVALID_GRANT.getCode(), errorResponse.getCode());
        assertEquals(OAuth2Error.INVALID_GRANT.getDescription(), errorResponse.getDescription());
    }

    @Test
    void shouldReturn401WhenClientAuthFails() throws Exception {
        String tokenRequestBody =
                "code=12345&redirect_uri=http://test.com&grant_type=authorization_code&client_id=test_client_id";

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(tokenRequestBody);

        doThrow(new ClientAuthenticationException("error"))
                .when(mockTokenRequestValidator)
                .authenticateClient(any());

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);
        ErrorObject errorResponse = createErrorObjectFromResponse(response.getBody());

        assertEquals(HTTPResponse.SC_UNAUTHORIZED, response.getStatusCode());
        assertEquals(OAuth2Error.INVALID_CLIENT.getCode(), errorResponse.getCode());
        assertEquals(OAuth2Error.INVALID_CLIENT.getDescription(), errorResponse.getDescription());
    }

    @Test
    void shouldReturn400WhenAuthCodeIsUsedMoreThanOnce() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        String tokenRequestBody =
                "code=12345&redirect_uri=http://example.com&grant_type=authorization_code&client_id=test_client_id";
        event.setBody(tokenRequestBody);

        SessionItem authorizationCodeItem = new SessionItem();

        authorizationCodeItem.setAuthorizationCode(new AuthorizationCode().toString());
        authorizationCodeItem.setRedirectUri(URI.create("http://example.com"));
        authorizationCodeItem.setCreatedDate(Instant.now().getEpochSecond());
        authorizationCodeItem.setSessionId(PASSPORT_SESSION_ID);

        authorizationCodeItem.setAccessToken("test-access-token");
        authorizationCodeItem.setAccessTokenExchangedDateTime(Instant.now().toString());

        when(mockAuthorizationCodeService.getSessionByAuthCode(anyString()))
                .thenReturn(authorizationCodeItem);

        when(mockAccessTokenService.validateAuthorizationGrant(any()))
                .thenReturn(ValidationResult.createValidResult());

        SessionItem passportSessionItem = new SessionItem();
        passportSessionItem.setClientId(UUID.randomUUID().toString());

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        verify(mockAccessTokenService)
                .revokeAccessToken(authorizationCodeItem.getAccessToken());

        ErrorObject errorResponse = createErrorObjectFromResponse(response.getBody());

        assertEquals(HTTPResponse.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(OAuth2Error.INVALID_GRANT.getCode(), errorResponse.getCode());
        assertEquals("Authorization code used too many times", errorResponse.getDescription());
    }

    @Test
    void shouldReturn400WhenRevokingAccessTokenFails() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        String tokenRequestBody =
                "code=12345&redirect_uri=http://example.com&grant_type=authorization_code&client_id=test_client_id";
        event.setBody(tokenRequestBody);

        SessionItem authorizationCodeItem = new SessionItem();

        authorizationCodeItem.setAuthorizationCode(new AuthorizationCode().toString());
        authorizationCodeItem.setRedirectUri(URI.create("http://example.com"));
        authorizationCodeItem.setCreatedDate(Instant.now().getEpochSecond());
        authorizationCodeItem.setSessionId(PASSPORT_SESSION_ID);

        authorizationCodeItem.setAccessToken("test-access-token");
        authorizationCodeItem.setAccessTokenExchangedDateTime(Instant.now().toString());

        when(mockAuthorizationCodeService.getSessionByAuthCode(anyString()))
                .thenReturn(authorizationCodeItem);

        when(mockAccessTokenService.validateAuthorizationGrant(any()))
                .thenReturn(ValidationResult.createValidResult());

        String errorMessage = "Failed to revoke access token";
        doThrow(new IllegalArgumentException(errorMessage))
                .when(mockAccessTokenService)
                .revokeAccessToken(any());

        SessionItem passportSessionItem = new SessionItem();
        passportSessionItem.setClientId(UUID.randomUUID().toString());

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        verify(mockAccessTokenService)
                .revokeAccessToken(authorizationCodeItem.getAccessToken());

        ErrorObject errorResponse = createErrorObjectFromResponse(response.getBody());

        assertEquals(HTTPResponse.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(OAuth2Error.INVALID_GRANT.getCode(), errorResponse.getCode());
        assertEquals(errorMessage, errorResponse.getDescription());
    }

    private ErrorObject createErrorObjectFromResponse(String responseBody) throws ParseException {
        HTTPResponse httpErrorResponse = new HTTPResponse(HttpStatus.SC_BAD_REQUEST);
        httpErrorResponse.setContentType(ContentType.APPLICATION_JSON.getType());
        httpErrorResponse.setContent(responseBody);
        return ErrorObject.parse(httpErrorResponse);
    }
}
