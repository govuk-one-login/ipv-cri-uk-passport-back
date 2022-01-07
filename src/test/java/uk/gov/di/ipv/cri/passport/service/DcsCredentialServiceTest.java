package uk.gov.di.ipv.cri.passport.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.passport.persistence.DataStore;
import uk.gov.di.ipv.cri.passport.persistence.item.DcsResponseItem;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DcsCredentialServiceTest {

    @Mock private ConfigurationService mockConfigurationService;

    @Mock private DataStore<DcsResponseItem> mockDataStore;

    private DcsCredentialService dcsCredentialService;

    @BeforeEach
    void setUp() {
        dcsCredentialService = new DcsCredentialService(mockConfigurationService, mockDataStore);
    }

    @Test
    void shouldReturnCredentialsFromDataStore() {
        DcsResponseItem dcsCredential = new DcsResponseItem();
        dcsCredential.setResourceId(UUID.randomUUID().toString());
        dcsCredential.setResourcePayload("test dcs resource payload");

        when(mockDataStore.getItem(anyString())).thenReturn(dcsCredential);

        DcsResponseItem credential = dcsCredentialService.getDcsCredential("dcs-credential-id-1");

        assertEquals(dcsCredential.getResourceId(), credential.getResourceId());
        assertEquals(dcsCredential.getResourcePayload(), credential.getResourcePayload());
    }
}
