package uk.gov.di.ipv.cri.passport.library.service;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.passport.library.persistence.DataStore;
import uk.gov.di.ipv.cri.passport.library.persistence.item.AuthorizationCodeItem;

import java.util.Objects;

public class AuthorizationCodeService {
    private final DataStore<AuthorizationCodeItem> dataStore;

    @ExcludeFromGeneratedCoverageReport
    public AuthorizationCodeService(ConfigurationService configurationService) {
        this.dataStore =
                new DataStore<>(
                        configurationService.getAuthCodesTableName(),
                        AuthorizationCodeItem.class,
                        DataStore.getClient(configurationService.getDynamoDbEndpointOverride()));
    }

    public AuthorizationCodeService(DataStore<AuthorizationCodeItem> dataStore) {
        this.dataStore = dataStore;
    }

    public AuthorizationCode generateAuthorizationCode() {
        return new AuthorizationCode();
    }

    public String getResourceIdByAuthorizationCode(String authorizationCode) {
        AuthorizationCodeItem authorizationCodeItem = dataStore.getItem(authorizationCode);
        return Objects.isNull(authorizationCodeItem) ? null : authorizationCodeItem.getResourceId();
    }

    public void persistAuthorizationCode(String authorizationCode, String resourceId) {
        AuthorizationCodeItem authorizationCodeItem = new AuthorizationCodeItem();
        authorizationCodeItem.setAuthCode(authorizationCode);
        authorizationCodeItem.setResourceId(resourceId);

        dataStore.create(authorizationCodeItem);
    }

    public void revokeAuthorizationCode(String authorizationCode) {
        dataStore.delete(authorizationCode);
    }
}
