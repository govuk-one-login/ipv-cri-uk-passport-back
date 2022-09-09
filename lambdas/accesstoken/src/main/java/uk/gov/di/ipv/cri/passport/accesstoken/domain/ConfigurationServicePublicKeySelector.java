package uk.gov.di.ipv.cri.passport.accesstoken.domain;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.auth.verifier.ClientCredentialsSelector;
import com.nimbusds.oauth2.sdk.auth.verifier.Context;
import com.nimbusds.oauth2.sdk.auth.verifier.InvalidClientException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import uk.gov.di.ipv.cri.passport.library.config.PassportConfigurationService;

import java.security.PublicKey;
import java.text.ParseException;
import java.util.List;

public class ConfigurationServicePublicKeySelector implements ClientCredentialsSelector<Object> {

    private final PassportConfigurationService passportConfigurationService;

    public ConfigurationServicePublicKeySelector(
            PassportConfigurationService passportConfigurationService) {
        this.passportConfigurationService = passportConfigurationService;
    }

    @Override
    public List<Secret> selectClientSecrets(
            ClientID claimedClientID, ClientAuthenticationMethod authMethod, Context context) {
        throw new UnsupportedOperationException("We don't do that round here...");
    }

    @Override
    public List<? extends PublicKey> selectPublicKeys(
            ClientID claimedClientID,
            ClientAuthenticationMethod authMethod,
            JWSHeader jwsHeader,
            boolean forceRefresh,
            Context context)
            throws InvalidClientException {
        try {
            return List.of(
                    passportConfigurationService
                            .getClientSigningPublicJwk(claimedClientID.getValue())
                            .toECPublicKey());
        } catch (ParseException | JOSEException e) {
            throw new InvalidClientException(e.getMessage());
        }
    }
}
