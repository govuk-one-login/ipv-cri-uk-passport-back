package uk.gov.di.ipv.cri.passport.library.service;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import org.apache.commons.codec.digest.DigestUtils;
import uk.gov.di.ipv.cri.common.library.persistence.item.SessionItem;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.passport.library.config.ConfigurationService;
import uk.gov.di.ipv.cri.passport.library.persistence.DataStore;

import java.net.URI;
import java.time.Instant;

import static uk.gov.di.ipv.cri.passport.library.config.ConfigurationVariable.AUTH_CODE_EXPIRY_CODE_SECONDS;
import static uk.gov.di.ipv.cri.passport.library.config.EnvironmentVariable.CRI_PASSPORT_AUTH_CODES_TABLE_NAME;

public class AuthorizationCodeService {
    private final DataStore<SessionItem> dataStore;
    private final ConfigurationService configurationService;

    @ExcludeFromGeneratedCoverageReport
    public AuthorizationCodeService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.dataStore =
                new DataStore<>(
                        configurationService.getEnvironmentVariable(
                                CRI_PASSPORT_AUTH_CODES_TABLE_NAME),
                        SessionItem.class,
                        DataStore.getClient(configurationService.getDynamoDbEndpointOverride()),
                        configurationService);
    }

    public AuthorizationCodeService(
            DataStore<SessionItem> dataStore, ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.dataStore = dataStore;
    }

    public AuthorizationCode generateAuthorizationCode() {
        return new AuthorizationCode();
    }

    public SessionItem getSessionByAuthCode(String authorizationCode) {
        return dataStore.getItem(DigestUtils.sha256Hex(authorizationCode));
    }

    public void persistAuthorizationCode(
            String authorizationCode,
            String resourceId,
            String redirectUrl,
            SessionItem passportSessionItem) {
        passportSessionItem.setRedirectUri(URI.create(redirectUrl));
        passportSessionItem.setAuthorizationCode(DigestUtils.sha256Hex(authorizationCode));
        passportSessionItem.setAuthCodeCreatedDateTime(Instant.now().toString());
        dataStore.update(passportSessionItem);
    }

    public void persistAuthorizationCode(String authorizationCode, SessionItem passportSessionItem) {
        passportSessionItem.setAuthorizationCode(DigestUtils.sha256Hex(authorizationCode));
        passportSessionItem.setAuthCodeCreatedDateTime(Instant.now().toString());
        dataStore.update(passportSessionItem);
    }

    public void setIssuedAccessToken(SessionItem authorizationCodeItem, String accessToken) {
        authorizationCodeItem.setAccessToken(DigestUtils.sha256Hex(accessToken));
        authorizationCodeItem.setAccessTokenExchangedDateTime(Instant.now().toString());

        dataStore.update(authorizationCodeItem);
    }

    public boolean isExpired(SessionItem authCodeItem) {
        return Instant.parse(authCodeItem.getAuthCodeCreatedDateTime())
                .isBefore(
                        Instant.now()
                                .minusSeconds(
                                        Long.parseLong(
                                                configurationService.getSsmParameter(
                                                        AUTH_CODE_EXPIRY_CODE_SECONDS))));
    }
}
