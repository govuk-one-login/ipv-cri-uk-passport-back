package uk.gov.di.ipv.cri.passport.service;

import uk.gov.di.ipv.cri.passport.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.passport.persistence.DataStore;
import uk.gov.di.ipv.cri.passport.persistence.item.DcsResponseItem;

public class DcsCredentialService {
    private final ConfigurationService configurationService;
    private final DataStore<DcsResponseItem> dataStore;

    @ExcludeFromGeneratedCoverageReport
    public DcsCredentialService() {
        this.configurationService = new ConfigurationService();
        this.dataStore =
                new DataStore<>(
                        configurationService.getDcsResponseTableName(),
                        DcsResponseItem.class,
                        DataStore.getClient());
    }

    public DcsCredentialService(
            ConfigurationService configurationService, DataStore<DcsResponseItem> dataStore) {
        this.configurationService = configurationService;
        this.dataStore = dataStore;
    }

    public DcsResponseItem getDcsCredential(String resourceId) {
        return dataStore.getItem(resourceId);
    }
}
