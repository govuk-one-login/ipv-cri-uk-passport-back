package uk.gov.di.ipv.cri.passport.library.service;

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
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
import uk.gov.di.ipv.cri.passport.library.persistence.DataStore;
import uk.gov.di.ipv.cri.passport.library.persistence.item.AccessTokenItem;
import uk.gov.di.ipv.cri.passport.library.validation.ValidationResult;

import java.net.URI;
import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AccessTokenServiceTest {

    @Mock private DataStore<AccessTokenItem> mockDataStore;
    @Mock private ConfigurationService mockConfigurationService;

    private AccessTokenService accessTokenService;

    @BeforeEach
    void setUp() {
        this.accessTokenService = new AccessTokenService(mockDataStore, mockConfigurationService);
    }

    @Test
    void shouldReturnSuccessfulTokenResponseOnSuccessfulExchange() throws Exception {
        long testTokenTtl = 2400L;
        Scope testScope = new Scope("test-scope");
        TokenRequest tokenRequest =
                new TokenRequest(
                        null,
                        new ClientID("test-client-id"),
                        new AuthorizationCodeGrant(
                                new AuthorizationCode("123456"), new URI("http://test.com")),
                        testScope);
        when(mockConfigurationService.getAccessTokenExpirySeconds()).thenReturn(testTokenTtl);

        TokenResponse response = accessTokenService.generateAccessToken(tokenRequest);

        assertInstanceOf(AccessTokenResponse.class, response);
        assertNotNull(response.toSuccessResponse().getTokens().getAccessToken().getValue());
        assertEquals(
                testTokenTtl,
                response.toSuccessResponse().getTokens().getBearerAccessToken().getLifetime());
        assertEquals(
                testScope,
                response.toSuccessResponse().getTokens().getBearerAccessToken().getScope());
    }

    @Test
    void shouldReturnValidationErrorWhenInvalidGrantTypeProvided() {
        TokenRequest tokenRequest =
                new TokenRequest(
                        null,
                        new ClientID("test-client-id"),
                        new RefreshTokenGrant(new RefreshToken()));

        ValidationResult<ErrorObject> validationResult =
                accessTokenService.validateTokenRequest(tokenRequest);

        assertNotNull(validationResult);
        assertFalse(validationResult.isValid());
        assertEquals(OAuth2Error.UNSUPPORTED_GRANT_TYPE, validationResult.getError());
    }

    @Test
    void shouldNotReturnValidationErrorWhenAValidTokenRequestIsProvided() {
        TokenRequest tokenRequest =
                new TokenRequest(
                        null,
                        new ClientID("test-client-id"),
                        new AuthorizationCodeGrant(
                                new AuthorizationCode(), URI.create("https://test.com")));

        ValidationResult<ErrorObject> validationResult =
                accessTokenService.validateTokenRequest(tokenRequest);

        assertNotNull(validationResult);
        assertTrue(validationResult.isValid());
        assertNull(validationResult.getError());
    }

    @Test
    void shouldPersistAccessToken() {
        String testResourceId = UUID.randomUUID().toString();
        String testPassportSessionId = UUID.randomUUID().toString();
        AccessToken accessToken = new BearerAccessToken(3600L, null);
        AccessTokenResponse accessTokenResponse =
                new AccessTokenResponse(new Tokens(accessToken, null));
        ArgumentCaptor<AccessTokenItem> accessTokenItemArgCaptor =
                ArgumentCaptor.forClass(AccessTokenItem.class);

        accessTokenService.persistAccessToken(
                accessTokenResponse, testResourceId, testPassportSessionId);

        verify(mockDataStore).create(accessTokenItemArgCaptor.capture());
        AccessTokenItem capturedAccessTokenItem = accessTokenItemArgCaptor.getValue();
        assertNotNull(capturedAccessTokenItem);
        assertEquals(testResourceId, capturedAccessTokenItem.getResourceId());
        assertEquals(testPassportSessionId, capturedAccessTokenItem.getPassportSessionId());
        assertEquals(
                DigestUtils.sha256Hex(
                        accessTokenResponse.getTokens().getBearerAccessToken().getValue()),
                capturedAccessTokenItem.getAccessToken());
        assertEquals(testResourceId, capturedAccessTokenItem.getResourceId());
        assertNotNull(capturedAccessTokenItem.getAccessTokenExpiryDateTime());
    }

    @Test
    void shouldGetSessionIdByAccessTokenWhenValidAccessTokenProvided() {
        String testResourceId = UUID.randomUUID().toString();
        AccessToken accessToken = new BearerAccessToken();
        String accessTokenValue = accessToken.toAuthorizationHeader();
        String testPassportSessionId = UUID.randomUUID().toString();

        AccessTokenItem accessTokenItem =
                new AccessTokenItem(
                        DigestUtils.sha256Hex(accessTokenValue),
                        testResourceId,
                        Instant.now().toString(),
                        testPassportSessionId);
        accessTokenItem.setResourceId(testResourceId);
        when(mockDataStore.getItem(DigestUtils.sha256Hex(accessTokenValue)))
                .thenReturn(accessTokenItem);

        AccessTokenItem result = accessTokenService.getAccessTokenItem(accessTokenValue);

        verify(mockDataStore).getItem(DigestUtils.sha256Hex(accessTokenValue));

        assertNotNull(result.getResourceId());
        assertEquals(testResourceId, result.getResourceId());
    }

    @Test
    void shouldReturnNullWhenInvalidAccessTokenProvided() {
        String accessToken = new BearerAccessToken().toAuthorizationHeader();

        when(mockDataStore.getItem(DigestUtils.sha256Hex(accessToken))).thenReturn(null);

        AccessTokenItem accessTokenItem = accessTokenService.getAccessTokenItem(accessToken);

        verify(mockDataStore).getItem(DigestUtils.sha256Hex(accessToken));
        assertNull(accessTokenItem);
    }

    @Test
    void shouldRevokeAccessToken() {
        String accessToken = "test-access-token";

        AccessTokenItem accessTokenItem =
                new AccessTokenItem(
                        accessToken,
                        UUID.randomUUID().toString(),
                        Instant.now().toString(),
                        UUID.randomUUID().toString());

        when(mockDataStore.getItem(accessToken)).thenReturn(accessTokenItem);

        accessTokenService.revokeAccessToken(accessToken);

        ArgumentCaptor<AccessTokenItem> accessTokenItemArgCaptor =
                ArgumentCaptor.forClass(AccessTokenItem.class);

        verify(mockDataStore).update(accessTokenItemArgCaptor.capture());
        assertNotNull(accessTokenItemArgCaptor.getValue().getRevokedAtDateTime());
    }

    @Test
    void shouldNotAttemptUpdateIfAccessTokenIsAlreadyRevoked() {
        String accessToken = "test-access-token";

        AccessTokenItem accessTokenItem =
                new AccessTokenItem(
                        accessToken,
                        UUID.randomUUID().toString(),
                        Instant.now().toString(),
                        UUID.randomUUID().toString());
        accessTokenItem.setRevokedAtDateTime(Instant.now().toString());

        when(mockDataStore.getItem(accessToken)).thenReturn(accessTokenItem);

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
