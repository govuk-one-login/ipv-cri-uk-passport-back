package uk.gov.di.ipv.cri.passport.library.service;

import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.passport.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.cri.passport.library.persistence.DataStore;
import uk.gov.di.ipv.cri.passport.library.persistence.item.PassportSessionItem;

import java.text.ParseException;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PassportSessionServiceTest {
    @Mock ConfigurationService configurationService;
    @Mock DataStore<PassportSessionItem> dataStore;

    private PassportSessionService underTest;

    @BeforeEach
    void setUp() {
        underTest = new PassportSessionService(dataStore, configurationService);
    }

    @Test
    void shouldReturnSessionItem() {
        String passportSessionID = SecureTokenHelper.generate();

        PassportSessionItem passportSessionItem = new PassportSessionItem();
        passportSessionItem.setPassportSessionId(passportSessionID);
        passportSessionItem.setCreationDateTime(new Date().toString());

        when(dataStore.getItem(passportSessionID)).thenReturn(passportSessionItem);

        PassportSessionItem result = underTest.getPassportSession(passportSessionID);

        ArgumentCaptor<String> passportSessionIDArgumentCaptor =
                ArgumentCaptor.forClass(String.class);
        verify(dataStore).getItem(passportSessionIDArgumentCaptor.capture());
        assertEquals(passportSessionID, passportSessionIDArgumentCaptor.getValue());
        assertEquals(passportSessionItem.getPassportSessionId(), result.getPassportSessionId());
        assertEquals(passportSessionItem.getCreationDateTime(), result.getCreationDateTime());
    }

    @Test
    void shouldCreateSessionItem() throws ParseException {
        JWTClaimsSet jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .claim("redirect_url", "http://example.com")
                        .claim("client_id", "ipv-core")
                        .build();

        String passportSessionID = underTest.generatePassportSession(jwtClaimsSet);

        ArgumentCaptor<PassportSessionItem> passportSessionItemArgumentCaptor =
                ArgumentCaptor.forClass(PassportSessionItem.class);
        verify(dataStore).create(passportSessionItemArgumentCaptor.capture());
        assertNotNull(passportSessionItemArgumentCaptor.getValue().getCreationDateTime());
        assertEquals(
                passportSessionItemArgumentCaptor.getValue().getPassportSessionId(),
                passportSessionID);
    }
}
