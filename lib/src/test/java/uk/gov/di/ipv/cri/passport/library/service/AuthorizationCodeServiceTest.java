package uk.gov.di.ipv.cri.passport.library.service;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.passport.library.persistence.DataStore;
import uk.gov.di.ipv.cri.passport.library.persistence.item.AuthorizationCodeItem;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthorizationCodeServiceTest {

    @Mock private DataStore<AuthorizationCodeItem> mockDataStore;
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
        authorizationCodeService.persistAuthorizationCode(
                testCode.getValue(), resourceId, redirectUrl);

        ArgumentCaptor<AuthorizationCodeItem> authorizationCodeItemArgumentCaptor =
                ArgumentCaptor.forClass(AuthorizationCodeItem.class);
        verify(mockDataStore).create(authorizationCodeItemArgumentCaptor.capture());
        assertEquals(resourceId, authorizationCodeItemArgumentCaptor.getValue().getResourceId());
        assertEquals(
                DigestUtils.sha256Hex(testCode.getValue()),
                authorizationCodeItemArgumentCaptor.getValue().getAuthCode());
        assertEquals(redirectUrl, authorizationCodeItemArgumentCaptor.getValue().getRedirectUrl());
    }

    @Test
    void shouldGetResourceIdByAuthCodeWhenValidAuthCodeProvided() {
        AuthorizationCode testCode = new AuthorizationCode();
        String resourceId = "resource-12345";

        AuthorizationCodeItem testItem = new AuthorizationCodeItem();
        testItem.setResourceId(resourceId);
        testItem.setAuthCode(new AuthorizationCode().getValue());
        testItem.setRedirectUrl("http://example.com");
        when(mockDataStore.getItem(DigestUtils.sha256Hex(testCode.getValue())))
                .thenReturn(testItem);

        AuthorizationCodeItem resultAuthCodeItem =
                authorizationCodeService.getAuthCodeItem(testCode.getValue());

        verify(mockDataStore).getItem(DigestUtils.sha256Hex(testCode.getValue()));
        assertEquals(resourceId, resultAuthCodeItem.getResourceId());
        assertEquals(testItem.getAuthCode(), resultAuthCodeItem.getAuthCode());
        assertEquals(testItem.getRedirectUrl(), resultAuthCodeItem.getRedirectUrl());
    }

    @Test
    void shouldReturnNullWhenInvalidAuthCodeProvided() {
        AuthorizationCode testCode = new AuthorizationCode();

        when(mockDataStore.getItem(DigestUtils.sha256Hex(testCode.getValue()))).thenReturn(null);

        AuthorizationCodeItem resultAuthCodeItem =
                authorizationCodeService.getAuthCodeItem(testCode.getValue());

        verify(mockDataStore).getItem(DigestUtils.sha256Hex(testCode.getValue()));
        assertNull(resultAuthCodeItem);
    }

    @Test
    void shouldCallDeleteWithAuthCode() {
        AuthorizationCode testCode = new AuthorizationCode();

        authorizationCodeService.revokeAuthorizationCode(testCode.getValue());

        verify(mockDataStore).delete(DigestUtils.sha256Hex(testCode.getValue()));
    }

    @Test
    void isExpiredReturnsTrueIfAuthCodeItemHasExpired() {
        when(configurationService.getAuthCodeExpirySeconds()).thenReturn(600L);
        AuthorizationCodeItem expiredAuthCodeItem =
                new AuthorizationCodeItem(
                        "auth-code",
                        "resource-id",
                        "redirect-url",
                        Instant.now().minusSeconds(601).toString());

        assertTrue(authorizationCodeService.isExpired(expiredAuthCodeItem));
    }

    @Test
    void isExpiredReturnsFalseIfAuthCodeItemHasNotExpired() {
        when(configurationService.getAuthCodeExpirySeconds()).thenReturn(600L);
        AuthorizationCodeItem expiredAuthCodeItem =
                new AuthorizationCodeItem(
                        "auth-code",
                        "resource-id",
                        "redirect-url",
                        Instant.now().minusSeconds(599).toString());

        assertFalse(authorizationCodeService.isExpired(expiredAuthCodeItem));
    }
}
