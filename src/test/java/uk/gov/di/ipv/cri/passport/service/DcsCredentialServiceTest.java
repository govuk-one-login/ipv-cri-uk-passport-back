package uk.gov.di.ipv.cri.passport.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.passport.domain.DcsResponse;
import uk.gov.di.ipv.cri.passport.domain.PassportFormRequest;
import uk.gov.di.ipv.cri.passport.persistence.DataStore;
import uk.gov.di.ipv.cri.passport.persistence.item.PassportCheckDao;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DcsCredentialServiceTest {

    @Mock private ConfigurationService mockConfigurationService;

    @Mock private DataStore<PassportCheckDao> mockDataStore;

    @Mock PassportFormRequest passportFormRequest;

    @Mock DcsResponse dcsResponse;

    private DcsCredentialService dcsCredentialService;

    @BeforeEach
    void setUp() {
        dcsCredentialService = new DcsCredentialService(mockConfigurationService, mockDataStore);
    }

    @Test
    void shouldReturnCredentialsFromDataStore() {
        PassportCheckDao passportCheckDao =
                new PassportCheckDao(
                        UUID.randomUUID().toString(), passportFormRequest, dcsResponse);

        when(mockDataStore.getItem(anyString())).thenReturn(passportCheckDao);

        PassportCheckDao credential = dcsCredentialService.getDcsCredential("dcs-credential-id-1");

        assertEquals(passportCheckDao.getResourceId(), credential.getResourceId());
        assertEquals(passportCheckDao.getPassportFormRequest(), passportFormRequest);
        assertEquals(passportCheckDao.getDcsResponse(), dcsResponse);
    }
}
