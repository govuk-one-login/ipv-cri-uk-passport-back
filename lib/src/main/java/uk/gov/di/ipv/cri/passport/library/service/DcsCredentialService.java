package uk.gov.di.ipv.cri.passport.library.service;

import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.passport.library.persistence.DataStore;
import uk.gov.di.ipv.cri.passport.library.persistence.item.PassportCheckDao;

public class DcsCredentialService {
    private final ConfigurationService configurationService;
    private final DataStore<PassportCheckDao> dataStore;

    @ExcludeFromGeneratedCoverageReport
    public DcsCredentialService() {
        this.configurationService = new ConfigurationService();
        this.dataStore =
                new DataStore<>(
                        configurationService.getDcsResponseTableName(),
                        PassportCheckDao.class,
                        DataStore.getClient(configurationService.getDynamoDbEndpointOverride()));
    }

    public DcsCredentialService(
            ConfigurationService configurationService, DataStore<PassportCheckDao> dataStore) {
        this.configurationService = configurationService;
        this.dataStore = dataStore;
    }

    public PassportCheckDao getDcsCredential(String resourceId) {
        return dataStore.getItem(resourceId);
    }
}
