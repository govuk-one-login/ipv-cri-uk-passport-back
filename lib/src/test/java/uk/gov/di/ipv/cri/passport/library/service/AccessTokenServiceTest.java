package uk.gov.di.ipv.cri.passport.library.service;

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.common.library.persistence.item.SessionItem;
import uk.gov.di.ipv.cri.passport.library.config.ConfigurationService;
import uk.gov.di.ipv.cri.passport.library.persistence.DataStore;
import uk.gov.di.ipv.cri.passport.library.validation.ValidationResult;

import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.cri.passport.library.service.AccessTokenService.DEFAULT_SCOPE;

@ExtendWith(MockitoExtension.class)
class AccessTokenServiceTest {

    @Mock private DataStore<SessionItem> mockDataStore;
    @Mock private ConfigurationService mockConfigurationService;

    private AccessTokenService accessTokenService;

    @BeforeEach
    void setUp() {
        this.accessTokenService = new AccessTokenService(mockDataStore, mockConfigurationService);
    }

    @Test
    void shouldReturnSuccessfulTokenResponseOnSuccessfulExchange() {
        long testTokenTtl = 2400L;
        when(mockConfigurationService.getAccessTokenExpirySeconds()).thenReturn(testTokenTtl);

        TokenResponse response = accessTokenService.generateAccessToken();

        assertInstanceOf(AccessTokenResponse.class, response);
        assertNotNull(response.toSuccessResponse().getTokens().getAccessToken().getValue());
        assertEquals(
                testTokenTtl,
                response.toSuccessResponse().getTokens().getBearerAccessToken().getLifetime());
        assertEquals(
                DEFAULT_SCOPE,
                response.toSuccessResponse().getTokens().getBearerAccessToken().getScope());
    }

    @Test
    void shouldReturnValidationErrorWhenInvalidGrantTypeProvided() {
        ValidationResult<ErrorObject> validationResult =
                accessTokenService.validateAuthorizationGrant(
                        new RefreshTokenGrant(new RefreshToken()));

        assertNotNull(validationResult);
        assertFalse(validationResult.isValid());
        assertEquals(OAuth2Error.UNSUPPORTED_GRANT_TYPE, validationResult.getError());
    }

    @Test
    void shouldPersistAccessToken() {
        AccessToken accessToken = new BearerAccessToken(3600L, null);
        AccessTokenResponse accessTokenResponse =
                new AccessTokenResponse(new Tokens(accessToken, null));
        ArgumentCaptor<SessionItem> SessionItemArgCaptor =
                ArgumentCaptor.forClass(SessionItem.class);

        SessionItem sessionItem = new SessionItem();
        accessTokenService.persistAccessToken(sessionItem,
                accessTokenResponse);

        verify(mockDataStore).update(SessionItemArgCaptor.capture());
        SessionItem capturedSessionItem = SessionItemArgCaptor.getValue();
        assertNotNull(capturedSessionItem);
        assertEquals(sessionItem.getSessionId(), capturedSessionItem.getSessionId());
        assertEquals(
                DigestUtils.sha256Hex(
                        accessTokenResponse.getTokens().getBearerAccessToken().getValue()),
                capturedSessionItem.getAccessToken());
        assertNotNull(capturedSessionItem.getAccessTokenExpiryDate());
    }

    @Test
    void shouldPersistAccessTokenWhenResourceIdNull() {
        AccessToken accessToken = new BearerAccessToken(3600L, null);
        AccessTokenResponse accessTokenResponse =
                new AccessTokenResponse(new Tokens(accessToken, null));
        ArgumentCaptor<SessionItem> SessionItemArgCaptor =
                ArgumentCaptor.forClass(SessionItem.class);

        SessionItem sessionItem = new SessionItem();
        accessTokenService.persistAccessToken(sessionItem, accessTokenResponse);

        verify(mockDataStore).update(SessionItemArgCaptor.capture());
        SessionItem capturedSessionItem = SessionItemArgCaptor.getValue();
        assertNotNull(capturedSessionItem);
        assertEquals(sessionItem.getSessionId(), capturedSessionItem.getSessionId());
        assertEquals(
                DigestUtils.sha256Hex(
                        accessTokenResponse.getTokens().getBearerAccessToken().getValue()),
                capturedSessionItem.getAccessToken());
        assertNotNull(capturedSessionItem.getAccessTokenExpiryDate());
    }

    @Test
    void shouldGetSessionIdByAccessTokenWhenValidAccessTokenProvided() {
        String testResourceId = UUID.randomUUID().toString();
        AccessToken accessToken = new BearerAccessToken();
        String accessTokenValue = accessToken.toAuthorizationHeader();
        String testPassportSessionId = UUID.randomUUID().toString();

        SessionItem SessionItem =
                new SessionItem();
        when(mockDataStore.getItem(DigestUtils.sha256Hex(accessTokenValue)))
                .thenReturn(SessionItem);

        SessionItem result = accessTokenService.getSessionByAccessToken(accessTokenValue);

        verify(mockDataStore).getItem(DigestUtils.sha256Hex(accessTokenValue));

    }

    @Test
    void shouldReturnNullWhenInvalidAccessTokenProvided() {
        String accessToken = new BearerAccessToken().toAuthorizationHeader();

        when(mockDataStore.getItem(DigestUtils.sha256Hex(accessToken))).thenReturn(null);

        SessionItem SessionItem = accessTokenService.getSessionByAccessToken(accessToken);

        verify(mockDataStore).getItem(DigestUtils.sha256Hex(accessToken));
        assertNull(SessionItem);
    }

    @Test
    void shouldRevokeAccessToken() {
        String accessToken = "test-access-token";

        SessionItem SessionItem =
                new SessionItem();

        when(mockDataStore.getItem(accessToken)).thenReturn(SessionItem);

        accessTokenService.revokeAccessToken(accessToken);

        ArgumentCaptor<SessionItem> SessionItemArgCaptor =
                ArgumentCaptor.forClass(SessionItem.class);

        verify(mockDataStore).update(SessionItemArgCaptor.capture());
        assertNotNull(SessionItemArgCaptor.getValue().getAccessTokenRevokedAtDateTime());
    }

    @Test
    void shouldNotAttemptUpdateIfAccessTokenIsAlreadyRevoked() {
        String accessToken = "test-access-token";

        SessionItem SessionItem =
                new SessionItem();
        SessionItem.setAccessTokenRevokedAtDateTime(Instant.now().toString());

        when(mockDataStore.getItem(accessToken)).thenReturn(SessionItem);

        accessTokenService.revokeAccessToken(accessToken);

        verify(mockDataStore, Mockito.times(0)).update(any());
    }

    @Test
    void shouldThrowExceptionIfAccessTokenCanNotBeFoundWhenRevoking() {
        String accessToken = "test-access-token";

        when(mockDataStore.getItem(accessToken)).thenReturn(null);

        try {
            accessTokenService.revokeAccessToken(accessToken);
            fail("Should have thrown an exception");
        } catch (IllegalArgumentException e) {
            assertEquals(
                    "Failed to revoke access token - access token could not be found in DynamoDB",
                    e.getMessage());
        }
    }
}
