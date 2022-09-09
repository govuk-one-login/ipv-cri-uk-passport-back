package uk.gov.di.ipv.cri.passport.library.service;

import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.passport.library.config.PassportConfigurationService;
import uk.gov.di.ipv.cri.passport.library.persistence.DataStore;
import uk.gov.di.ipv.cri.passport.library.persistence.item.ClientAuthJwtIdItem;

import java.time.Instant;

import static uk.gov.di.ipv.cri.passport.library.config.EnvironmentVariable.CRI_PASSPORT_CLIENT_AUTH_JWT_IDS_TABLE_NAME;

public class ClientAuthJwtIdService {
    private final DataStore<ClientAuthJwtIdItem> dataStore;
    private final PassportConfigurationService passportConfigurationService;

    @ExcludeFromGeneratedCoverageReport
    public ClientAuthJwtIdService(PassportConfigurationService passportConfigurationService) {
        this.passportConfigurationService = passportConfigurationService;
        this.dataStore =
                new DataStore<>(
                        this.passportConfigurationService.getEnvironmentVariable(
                                CRI_PASSPORT_CLIENT_AUTH_JWT_IDS_TABLE_NAME),
                        ClientAuthJwtIdItem.class,
                        DataStore.getClient(
                                this.passportConfigurationService.getDynamoDbEndpointOverride()),
                        this.passportConfigurationService);
    }

    // For tests
    public ClientAuthJwtIdService(
            PassportConfigurationService passportConfigurationService,
            DataStore<ClientAuthJwtIdItem> dataStore) {
        this.passportConfigurationService = passportConfigurationService;
        this.dataStore = dataStore;
    }

    public ClientAuthJwtIdItem getClientAuthJwtIdItem(String jwtId) {
        return dataStore.getItem(jwtId);
    }

    public void persistClientAuthJwtId(String jwtId) {
        String timestamp = Instant.now().toString();
        ClientAuthJwtIdItem clientAuthJwtIdItem = new ClientAuthJwtIdItem(jwtId, timestamp);
        dataStore.create(clientAuthJwtIdItem);
    }
}
