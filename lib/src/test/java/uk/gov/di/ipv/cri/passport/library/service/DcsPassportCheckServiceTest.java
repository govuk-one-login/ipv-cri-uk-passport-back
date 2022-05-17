package uk.gov.di.ipv.cri.passport.library.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.passport.library.domain.DcsPayload;
import uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.Evidence;
import uk.gov.di.ipv.cri.passport.library.persistence.DataStore;
import uk.gov.di.ipv.cri.passport.library.persistence.item.PassportCheckDao;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DcsPassportCheckServiceTest {

    @Mock private DataStore<PassportCheckDao> mockDataStore;

    @Mock DcsPayload dcsPayload;

    @Mock Evidence evidence;

    private DcsPassportCheckService dcsPassportCheckService;

    @BeforeEach
    void setUp() {
        dcsPassportCheckService = new DcsPassportCheckService(mockDataStore);
    }

    @Test
    void shouldReturnCredentialsFromDataStore() {
        PassportCheckDao passportCheckDao =
                new PassportCheckDao(
                        UUID.randomUUID().toString(),
                        dcsPayload,
                        evidence,
                        "test-user-id",
                        "a-client-id");

        when(mockDataStore.getItem(anyString())).thenReturn(passportCheckDao);

        PassportCheckDao credential =
                dcsPassportCheckService.getDcsPassportCheck("dcs-credential-id-1");

        assertEquals(passportCheckDao.getResourceId(), credential.getResourceId());
        assertEquals(passportCheckDao.getDcsPayload(), credential.getDcsPayload());
        assertEquals(passportCheckDao.getUserId(), credential.getUserId());
        assertEquals(passportCheckDao.getClientId(), credential.getClientId());
    }
}
