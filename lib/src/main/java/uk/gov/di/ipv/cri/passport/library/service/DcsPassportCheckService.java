package uk.gov.di.ipv.cri.passport.library.service;

import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.passport.library.persistence.DataStore;
import uk.gov.di.ipv.cri.passport.library.persistence.item.PassportCheckDao;

public class DcsPassportCheckService {
    private final DataStore<PassportCheckDao> dataStore;

    @ExcludeFromGeneratedCoverageReport
    public DcsPassportCheckService(ConfigurationService configurationService) {
        this.dataStore =
                new DataStore<>(
                        configurationService.getDcsResponseTableName(),
                        PassportCheckDao.class,
                        DataStore.getClient(configurationService.getDynamoDbEndpointOverride()));
    }

    public DcsPassportCheckService(DataStore<PassportCheckDao> dataStore) {
        this.dataStore = dataStore;
    }

    public PassportCheckDao getDcsPassportCheck(String resourceId) {
        return dataStore.getItem(resourceId);
    }
}
