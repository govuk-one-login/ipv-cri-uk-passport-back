package uk.gov.di.ipv.cri.passport.library.service;

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.passport.library.persistence.DataStore;
import uk.gov.di.ipv.cri.passport.library.persistence.item.AccessTokenItem;
import uk.gov.di.ipv.cri.passport.library.validation.ValidationResult;

import java.util.Objects;

public class AccessTokenService {
    private final DataStore<AccessTokenItem> dataStore;
    private final ConfigurationService configurationService;

    @ExcludeFromGeneratedCoverageReport
    public AccessTokenService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.dataStore =
                new DataStore<>(
                        this.configurationService.getAccessTokensTableName(),
                        AccessTokenItem.class,
                        DataStore.getClient(
                                this.configurationService.getDynamoDbEndpointOverride()),
                        this.configurationService);
    }

    public AccessTokenService(
            DataStore<AccessTokenItem> dataStore, ConfigurationService configurationService) {
        this.dataStore = dataStore;
        this.configurationService = configurationService;
    }

    public TokenResponse generateAccessToken(TokenRequest tokenRequest) {
        AccessToken accessToken =
                new BearerAccessToken(
                        configurationService.getBearerAccessTokenTtl(), tokenRequest.getScope());
        return new AccessTokenResponse(new Tokens(accessToken, null));
    }

    public ValidationResult<ErrorObject> validateTokenRequest(TokenRequest tokenRequest) {
        if (!tokenRequest.getAuthorizationGrant().getType().equals(GrantType.AUTHORIZATION_CODE)) {
            return new ValidationResult<>(false, OAuth2Error.UNSUPPORTED_GRANT_TYPE);
        }
        return ValidationResult.createValidResult();
    }

    public String getResourceIdByAccessToken(String accessToken) {
        AccessTokenItem accessTokenItem = dataStore.getItem(accessToken);
        return Objects.isNull(accessTokenItem) ? null : accessTokenItem.getResourceId();
    }

    public void persistAccessToken(AccessTokenResponse tokenResponse, String resourceId) {
        AccessTokenItem accessTokenItem = new AccessTokenItem();
        accessTokenItem.setAccessToken(
                tokenResponse.getTokens().getBearerAccessToken().toAuthorizationHeader());
        accessTokenItem.setResourceId(resourceId);
        dataStore.create(accessTokenItem);
    }
}
