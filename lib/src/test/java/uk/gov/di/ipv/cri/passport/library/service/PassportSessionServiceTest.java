package uk.gov.di.ipv.cri.passport.library.service;

import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.common.library.persistence.item.SessionItem;
import uk.gov.di.ipv.cri.passport.library.config.ConfigurationService;
import uk.gov.di.ipv.cri.passport.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.cri.passport.library.persistence.DataStore;

import java.text.ParseException;
import java.util.Date;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PassportSessionServiceTest {
    @Mock ConfigurationService configurationService;
    @Mock DataStore<SessionItem> mockDataStore;

    private PassportSessionService underTest;

    @BeforeEach
    void setUp() {
        underTest = new PassportSessionService(mockDataStore, configurationService);
    }

    @Test
    void shouldReturnSessionItem() {
        SessionItem passportSessionItem = new SessionItem();

        UUID passportSessionID = passportSessionItem.getSessionId();

        passportSessionItem.setSessionId(passportSessionID);
        passportSessionItem.setAuthCodeCreatedDateTime(new Date().toString());

        when(mockDataStore.getItem(passportSessionID.toString())).thenReturn(passportSessionItem);

        SessionItem result = underTest.getPassportSession(passportSessionID.toString());

        ArgumentCaptor<String> passportSessionIDArgumentCaptor =
                ArgumentCaptor.forClass(String.class);
        verify(mockDataStore).getItem(passportSessionIDArgumentCaptor.capture());
        assertEquals(passportSessionID.toString(), passportSessionIDArgumentCaptor.getValue());
        assertEquals(passportSessionItem.getSessionId(), result.getSessionId());
        assertEquals(passportSessionItem.getAuthCodeCreatedDateTime(), result.getAuthCodeCreatedDateTime());
    }

    @Test
    void shouldCreateSessionItem() throws ParseException {
        JWTClaimsSet jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .claim("redirect_uri", "http://example.com")
                        .claim("client_id", "ipv-core")
                        .build();

        SessionItem passportSessionItem = underTest.generatePassportSession(jwtClaimsSet);

        ArgumentCaptor<SessionItem> passportSessionItemArgumentCaptor =
                ArgumentCaptor.forClass(SessionItem.class);
        verify(mockDataStore).create(passportSessionItemArgumentCaptor.capture());
        assertNotNull(passportSessionItemArgumentCaptor.getValue().getCreatedDate());
        assertEquals(
                passportSessionItemArgumentCaptor.getValue().getSessionId(),
                passportSessionItem.getSessionId());
    }

    @Test
    void shouldUpdateLatestDcsResponseResourceId() {
        String passportSessionID = SecureTokenHelper.generate();
        String latestDcsResponseResourceId = "test";

        when(mockDataStore.getItem(passportSessionID)).thenReturn(new SessionItem());
        underTest.setLatestDcsResponseResourceId(passportSessionID, latestDcsResponseResourceId);

        ArgumentCaptor<SessionItem> passportSessionItemArgumentCaptor =
                ArgumentCaptor.forClass(SessionItem.class);
        verify(mockDataStore).update(passportSessionItemArgumentCaptor.capture());
        assertEquals(
                passportSessionItemArgumentCaptor.getValue().getLatestDcsResponseResourceId(),
                latestDcsResponseResourceId);
    }

    @Test
    void shouldIncrementAttemptCount() {
        String passportSessionID = SecureTokenHelper.generate();

        SessionItem passportSessionItem = new SessionItem();
        passportSessionItem.setAttemptCount(1);

        when(mockDataStore.getItem(passportSessionID)).thenReturn(passportSessionItem);
        underTest.incrementAttemptCount(passportSessionID);

        ArgumentCaptor<SessionItem> passportSessionItemArgumentCaptor =
                ArgumentCaptor.forClass(SessionItem.class);
        verify(mockDataStore).update(passportSessionItemArgumentCaptor.capture());
        assertEquals(2, passportSessionItemArgumentCaptor.getValue().getAttemptCount());
    }
}
