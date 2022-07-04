package uk.gov.di.ipv.cri.passport.library.service;

import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.passport.library.persistence.DataStore;
import uk.gov.di.ipv.cri.passport.library.persistence.item.ClientAuthJwtIdItem;

import java.time.Instant;

public class ClientAuthJwtIdService {
    private final DataStore<ClientAuthJwtIdItem> dataStore;
    private final ConfigurationService configurationService;

    @ExcludeFromGeneratedCoverageReport
    public ClientAuthJwtIdService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.dataStore =
                new DataStore<>(
                        this.configurationService.getClientAuthJwtIdsTableName(),
                        ClientAuthJwtIdItem.class,
                        DataStore.getClient(
                                this.configurationService.getDynamoDbEndpointOverride()),
                        this.configurationService);
    }

    // For tests
    public ClientAuthJwtIdService(
            ConfigurationService configurationService, DataStore<ClientAuthJwtIdItem> dataStore) {
        this.configurationService = configurationService;
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
