package uk.gov.di.ipv.cri.passport.accesstoken.validation;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.JWTAuthenticationClaimsSet;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.auth.verifier.ClientAuthenticationVerifier;
import com.nimbusds.oauth2.sdk.auth.verifier.InvalidClientException;
import com.nimbusds.oauth2.sdk.id.Audience;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.cri.passport.accesstoken.domain.ConfigurationServicePublicKeySelector;
import uk.gov.di.ipv.cri.passport.accesstoken.exceptions.ClientAuthenticationException;
import uk.gov.di.ipv.cri.passport.library.helpers.JwtHelper;
import uk.gov.di.ipv.cri.passport.library.helpers.RequestHelper;
import uk.gov.di.ipv.cri.passport.library.service.ConfigurationService;

import java.time.OffsetDateTime;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class TokenRequestValidator {
    private static final Logger LOGGER = LoggerFactory.getLogger(TokenRequestValidator.class);
    private static final String CLIENT_ASSERTION_PARAM = "client_assertion";

    private final ConfigurationService configurationService;

    private final ClientAuthenticationVerifier<Object> verifier;

    public TokenRequestValidator(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.verifier = getClientAuthVerifier(configurationService);
    }

    public void authenticateClient(String requestBody) throws ClientAuthenticationException {
        PrivateKeyJWT clientJwt;
        try {
            clientJwt = PrivateKeyJWT.parse(requestBody);
            verifier.verify(clientJwtWithConcatSignature(clientJwt, requestBody), null, null);
            validateMaxAllowedAuthClientTtl(clientJwt.getJWTAuthenticationClaimsSet());
        } catch (ParseException
                | InvalidClientException
                | JOSEException
                | java.text.ParseException e) {
            LOGGER.error("Validation of client_assertion jwt failed");
            throw new ClientAuthenticationException(e);
        }
    }

    private void validateMaxAllowedAuthClientTtl(JWTAuthenticationClaimsSet claimsSet)
            throws InvalidClientException {
        Date expirationTime = claimsSet.getExpirationTime();
        String maxAllowedTtl = configurationService.getMaxClientAuthTokenTtl();

        OffsetDateTime offsetDateTime =
                OffsetDateTime.now().plusSeconds(Long.parseLong(maxAllowedTtl));
        if (expirationTime.getTime() / 1000L > offsetDateTime.toEpochSecond()) {
            LOGGER.error("Client JWT expiry date is too far in the future");
            throw new InvalidClientException(
                    "The client JWT expiry date has surpassed the maximum allowed ttl value");
        }
    }

    private ClientAuthenticationVerifier<Object> getClientAuthVerifier(
            ConfigurationService configurationService) {

        ConfigurationServicePublicKeySelector configurationServicePublicKeySelector =
                new ConfigurationServicePublicKeySelector(configurationService);
        return new ClientAuthenticationVerifier<>(
                configurationServicePublicKeySelector,
                Set.of(new Audience(configurationService.getAudienceForClients())));
    }

    private PrivateKeyJWT clientJwtWithConcatSignature(PrivateKeyJWT clientJwt, String requestBody)
            throws JOSEException, java.text.ParseException, ParseException {
        // AWS KMS EC signature are in DER format. We need them in concat format.
        return JwtHelper.signatureIsDerFormat(clientJwt.getClientAssertion())
                ? transcodeSignatureToConcatFormat(clientJwt, requestBody)
                : clientJwt;
    }

    private PrivateKeyJWT transcodeSignatureToConcatFormat(
            PrivateKeyJWT clientJwt, String requestBody)
            throws java.text.ParseException, JOSEException, ParseException {
        Map<String, String> queryStringMap = RequestHelper.parseRequestBody(requestBody);
        queryStringMap.put(
                CLIENT_ASSERTION_PARAM,
                JwtHelper.transcodeSignature(clientJwt.getClientAssertion()).serialize());
        Map<String, List<String>> queryStringMapForParsing =
                queryStringMap.entrySet().stream()
                        .collect(Collectors.toMap(Map.Entry::getKey, e -> List.of(e.getValue())));
        return PrivateKeyJWT.parse(queryStringMapForParsing);
    }
}
