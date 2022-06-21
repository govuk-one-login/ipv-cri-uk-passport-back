package uk.gov.di.ipv.cri.passport.library.service;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.passport.library.persistence.DataStore;
import uk.gov.di.ipv.cri.passport.library.persistence.item.AuthorizationCodeItem;

import java.time.Instant;

public class AuthorizationCodeService {
    private final DataStore<AuthorizationCodeItem> dataStore;
    private final ConfigurationService configurationService;

    @ExcludeFromGeneratedCoverageReport
    public AuthorizationCodeService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.dataStore =
                new DataStore<>(
                        configurationService.getAuthCodesTableName(),
                        AuthorizationCodeItem.class,
                        DataStore.getClient(configurationService.getDynamoDbEndpointOverride()),
                        configurationService);
    }

    public AuthorizationCodeService(
            DataStore<AuthorizationCodeItem> dataStore, ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.dataStore = dataStore;
    }

    public AuthorizationCode generateAuthorizationCode() {
        return new AuthorizationCode();
    }

    public AuthorizationCodeItem getAuthCodeItem(String authorizationCode) {
        return dataStore.getItem(authorizationCode);
    }

    public void persistAuthorizationCode(
            String authorizationCode, String resourceId, String redirectUrl) {
        dataStore.create(
                new AuthorizationCodeItem(
                        authorizationCode, resourceId, redirectUrl, Instant.now().toString()));
    }

    public void revokeAuthorizationCode(String authorizationCode) {
        dataStore.delete(authorizationCode);
    }

    public boolean isExpired(AuthorizationCodeItem authCodeItem) {
        return Instant.parse(authCodeItem.getCreationDateTime())
                .isBefore(
                        Instant.now()
                                .minusSeconds(configurationService.getAuthCodeExpirySeconds()));
    }
}
