package uk.gov.di.ipv.cri.passport.library.service;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.common.library.persistence.item.SessionItem;
import uk.gov.di.ipv.cri.passport.library.config.ConfigurationService;
import uk.gov.di.ipv.cri.passport.library.persistence.DataStore;

import java.net.URI;
import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.cri.passport.library.config.ConfigurationVariable.AUTH_CODE_EXPIRY_CODE_SECONDS;

@ExtendWith(MockitoExtension.class)
class AuthorizationCodeServiceTest {

    @Mock private DataStore<SessionItem> mockDataStore;
    @Mock private ConfigurationService configurationService;
    @InjectMocks AuthorizationCodeService authorizationCodeService;

    @Test
    void shouldReturnAnAuthorisationCode() {
        AuthorizationCode result = authorizationCodeService.generateAuthorizationCode();

        assertNotNull(result);
    }

    @Test
    void shouldCreateAuthorizationCodeInDataStore() {
        AuthorizationCode testCode = new AuthorizationCode();
        String resourceId = "resource-12345";
        String redirectUrl = "http://example.com";
        SessionItem passportSessionItem = new SessionItem();
        passportSessionItem.setRedirectUri(URI.create("http://example.com"));

        authorizationCodeService.persistAuthorizationCode(
                testCode.getValue(), passportSessionItem);

        ArgumentCaptor<SessionItem> authorizationCodeItemArgumentCaptor =
                ArgumentCaptor.forClass(SessionItem.class);
        verify(mockDataStore).update(authorizationCodeItemArgumentCaptor.capture());
        assertEquals(
                passportSessionItem.getSessionId(),
                authorizationCodeItemArgumentCaptor.getValue().getSessionId());
        assertEquals(
                DigestUtils.sha256Hex(testCode.getValue()),
                authorizationCodeItemArgumentCaptor.getValue().getAuthorizationCode());
        assertEquals(redirectUrl, authorizationCodeItemArgumentCaptor.getValue().getRedirectUri().toString());
    }

    @Test
    void shouldGetResourceIdByAuthCodeWhenValidAuthCodeProvided() {
        AuthorizationCode testCode = new AuthorizationCode();
        String resourceId = "resource-12345";

        SessionItem testItem = new SessionItem();
        testItem.setAuthorizationCode(new AuthorizationCode().getValue());
        testItem.setRedirectUri(URI.create("http://example.com"));
        when(mockDataStore.getItem(DigestUtils.sha256Hex(testCode.getValue())))
                .thenReturn(testItem);

        SessionItem resultAuthCodeItem =
                authorizationCodeService.getSessionByAuthCode(testCode.getValue());

        verify(mockDataStore).getItem(DigestUtils.sha256Hex(testCode.getValue()));
        assertEquals(testItem.getAuthorizationCode(), resultAuthCodeItem.getAuthorizationCode());
        assertEquals(testItem.getRedirectUri(), resultAuthCodeItem.getRedirectUri());
    }

    @Test
    void shouldReturnNullWhenInvalidAuthCodeProvided() {
        AuthorizationCode testCode = new AuthorizationCode();

        when(mockDataStore.getItem(DigestUtils.sha256Hex(testCode.getValue()))).thenReturn(null);

        SessionItem resultAuthCodeItem =
                authorizationCodeService.getSessionByAuthCode(testCode.getValue());

        verify(mockDataStore).getItem(DigestUtils.sha256Hex(testCode.getValue()));
        assertNull(resultAuthCodeItem);
    }

    @Test
    void shouldCallUpdateWithIssuedAccessTokenValue() {
        AuthorizationCode testCode = new AuthorizationCode();
        SessionItem authorizationCodeItem =
                new SessionItem();

        authorizationCodeService.setIssuedAccessToken(authorizationCodeItem, "test-access-token");

        ArgumentCaptor<SessionItem> authorizationCodeItemArgumentCaptor =
                ArgumentCaptor.forClass(SessionItem.class);
        verify(mockDataStore).update(authorizationCodeItemArgumentCaptor.capture());

        assertNotNull(authorizationCodeItemArgumentCaptor.getValue().getAccessTokenExchangedDateTime());
    }

    @Test
    void isExpiredReturnsTrueIfAuthCodeItemHasExpired() {
        when(configurationService.getSsmParameter(AUTH_CODE_EXPIRY_CODE_SECONDS)).thenReturn("600");
        SessionItem expiredAuthCodeItem =
                new SessionItem();
        expiredAuthCodeItem.setAuthorizationCode("auth-code");
        expiredAuthCodeItem.setRedirectUri(URI.create("http://example.com"));
        expiredAuthCodeItem.setAuthCodeCreatedDateTime(Instant.now().minusSeconds(601).toString());

        assertTrue(authorizationCodeService.isExpired(expiredAuthCodeItem));
    }

    @Test
    void isExpiredReturnsFalseIfAuthCodeItemHasNotExpired() {
        when(configurationService.getSsmParameter(AUTH_CODE_EXPIRY_CODE_SECONDS)).thenReturn("600");
        SessionItem expiredAuthCodeItem =
                new SessionItem();
        expiredAuthCodeItem.setAuthorizationCode("auth-code");
        expiredAuthCodeItem.setRedirectUri(URI.create("http://example.com"));
        expiredAuthCodeItem.setAuthCodeCreatedDateTime(Instant.now().minusSeconds(599).toString());

        assertFalse(authorizationCodeService.isExpired(expiredAuthCodeItem));
    }
}
