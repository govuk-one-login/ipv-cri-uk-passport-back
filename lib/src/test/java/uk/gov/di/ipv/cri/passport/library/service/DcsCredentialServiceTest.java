package uk.gov.di.ipv.cri.passport.library.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.passport.library.domain.DcsResponse;
import uk.gov.di.ipv.cri.passport.library.domain.PassportAttributes;
import uk.gov.di.ipv.cri.passport.library.domain.PassportGpg45Score;
import uk.gov.di.ipv.cri.passport.library.persistence.DataStore;
import uk.gov.di.ipv.cri.passport.library.persistence.item.PassportCheckDao;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DcsCredentialServiceTest {

    @Mock private ConfigurationService mockConfigurationService;

    @Mock private DataStore<PassportCheckDao> mockDataStore;

    @Mock PassportAttributes passportAttributes;

    @Mock PassportGpg45Score gpg45Score;

    @Mock DcsResponse dcsResponse;

    private DcsCredentialService dcsCredentialService;

    @BeforeEach
    void setUp() {
        dcsCredentialService = new DcsCredentialService(mockDataStore);
    }

    @Test
    void shouldReturnCredentialsFromDataStore() {
        PassportCheckDao passportCheckDao =
                new PassportCheckDao(UUID.randomUUID().toString(), passportAttributes, gpg45Score);

        when(mockDataStore.getItem(anyString())).thenReturn(passportCheckDao);

        PassportCheckDao credential = dcsCredentialService.getDcsCredential("dcs-credential-id-1");

        assertEquals(passportCheckDao.getResourceId(), credential.getResourceId());
        assertEquals(passportCheckDao.getAttributes(), credential.getAttributes());
        assertEquals(
                passportCheckDao.getAttributes().getDcsResponse(),
                credential.getAttributes().getDcsResponse());
    }
}
