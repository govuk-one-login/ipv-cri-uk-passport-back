package uk.gov.di.ipv.cri.passport.library.validation;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.services.ssm.model.ParameterNotFoundException;
import uk.gov.di.ipv.cri.passport.library.exceptions.SharedAttributesValidationException;
import uk.gov.di.ipv.cri.passport.library.helpers.JwtHelper;
import uk.gov.di.ipv.cri.passport.library.service.ConfigurationService;

import java.net.URI;
import java.text.ParseException;
import java.time.OffsetDateTime;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.List;

public class JarValidator {
    private static final Logger LOGGER = LoggerFactory.getLogger(JarValidator.class);
    private static final String REDIRECT_URI_CLAIM = "redirect_uri";

    private final ConfigurationService configurationService;

    public JarValidator(ConfigurationService configurationService) {
        this.configurationService = configurationService;
    }

    public SignedJWT decryptJWE(String jweString) throws SharedAttributesValidationException {
        try {
            JWEObject jweObject = JWEObject.parse(jweString);

            // Decrypt functionality to go here...

            return jweObject.getPayload().toSignedJWT();
        } catch (ParseException e) {
            LOGGER.error("Failed to parse request body into a JWE");
            throw new SharedAttributesValidationException(OAuth2Error.INVALID_REQUEST_OBJECT);
        }
    }

    public JWTClaimsSet validateRequestJwt(SignedJWT signedJWT, String clientId)
            throws SharedAttributesValidationException {
        validateClientId(clientId);
        validateJWTHeader(signedJWT, clientId);
        validateSignature(signedJWT, clientId);
        JWTClaimsSet claimsSet = validateClaimSet(signedJWT, clientId);
        validateRedirectUri(claimsSet, clientId);

        return claimsSet;
    }

    private void validateClientId(String clientId) throws SharedAttributesValidationException {
        try {
            configurationService.getClientAuthenticationMethod(clientId);
        } catch (ParameterNotFoundException e) {
            LOGGER.error("Unknown client id provided {}", clientId);
            throw new SharedAttributesValidationException(
                    OAuth2Error.INVALID_CLIENT.setDescription("Unknown client id was provided"));
        }
    }

    private void validateJWTHeader(SignedJWT signedJWT, String clientId)
            throws SharedAttributesValidationException {
        JWSAlgorithm configuredAlgorithm =
                JWSAlgorithm.parse(configurationService.getClientSigningAlgorithm(clientId));
        JWSAlgorithm jwtAlgorithm = signedJWT.getHeader().getAlgorithm();
        if (jwtAlgorithm != configuredAlgorithm) {
            LOGGER.error(
                    "jwt signing algorithm {} does not match signing algorithm configured for client: {}",
                    jwtAlgorithm,
                    configuredAlgorithm);
            throw new SharedAttributesValidationException(
                    OAuth2Error.INVALID_REQUEST_OBJECT.setDescription(
                            "Signing algorithm used does not match required algorithm configured for client"));
        }
    }

    private void validateSignature(SignedJWT signedJWT, String clientId)
            throws SharedAttributesValidationException {
        try {
            SignedJWT concatSignatureJwt;
            if (JwtHelper.signatureIsDerFormat(signedJWT)) {
                concatSignatureJwt = JwtHelper.transcodeSignature(signedJWT);
            } else {
                concatSignatureJwt = signedJWT;
            }
            boolean valid =
                    concatSignatureJwt.verify(
                            new ECDSAVerifier(
                                    configurationService.getClientSigningPublicJwk(clientId)));

            if (!valid) {
                LOGGER.error("JWT signature validation failed");
                throw new SharedAttributesValidationException(
                        OAuth2Error.INVALID_REQUEST_OBJECT.setDescription(
                                "JWT signature validation failed"));
            }
        } catch (JOSEException | ParseException e) {
            LOGGER.error("Failed to parse JWT when attempting signature validation");
            throw new SharedAttributesValidationException(
                    OAuth2Error.INVALID_REQUEST_OBJECT.setDescription(
                            "Failed to parse JWT when attempting signature validation"));
        }
    }

    private JWTClaimsSet validateClaimSet(SignedJWT signedJWT, String clientId)
            throws SharedAttributesValidationException {

        String criAudience = configurationService.getAudienceForClients();
        String clientIssuer = configurationService.getClientIssuer(clientId);

        DefaultJWTClaimsVerifier<?> verifier =
                new DefaultJWTClaimsVerifier<>(
                        criAudience,
                        new JWTClaimsSet.Builder()
                                .issuer(clientIssuer)
                                .claim("response_type", "code")
                                .build(),
                        new HashSet<>(
                                Arrays.asList(
                                        JWTClaimNames.EXPIRATION_TIME,
                                        JWTClaimNames.NOT_BEFORE,
                                        JWTClaimNames.ISSUED_AT,
                                        JWTClaimNames.SUBJECT)));

        try {
            verifier.verify(signedJWT.getJWTClaimsSet(), null);

            validateDateClaims(signedJWT.getJWTClaimsSet());

            return signedJWT.getJWTClaimsSet();
        } catch (BadJWTException | ParseException e) {
            LOGGER.error("Claim set validation failed");
            throw new SharedAttributesValidationException(
                    OAuth2Error.INVALID_GRANT.setDescription(e.getMessage()));
        }
    }

    private void validateDateClaims(JWTClaimsSet claimsSet)
            throws SharedAttributesValidationException {
        Date expirationTime = claimsSet.getExpirationTime();
        String maxAllowedTtl = configurationService.getMaxClientAuthTokenTtl();

        OffsetDateTime offsetDateTime =
                OffsetDateTime.now().plusSeconds(Long.parseLong(maxAllowedTtl));
        if (expirationTime.getTime() / 1000L > offsetDateTime.toEpochSecond()) {
            LOGGER.error("Client JWT expiry date is too far in the future");
            throw new SharedAttributesValidationException(
                    OAuth2Error.INVALID_GRANT.setDescription(
                            "The client JWT expiry date has surpassed the maximum allowed ttl value"));
        }
    }

    private void validateRedirectUri(JWTClaimsSet claimsSet, String clientId)
            throws SharedAttributesValidationException {
        try {
            URI redirectUri = claimsSet.getURIClaim(REDIRECT_URI_CLAIM);
            List<String> allowedRedirectUris = configurationService.getClientRedirectUrls(clientId);

            if (!allowedRedirectUris.contains(redirectUri.toString())) {
                LOGGER.error(
                        "Invalid redirect_uri claim ({}) provided for client: {}",
                        redirectUri,
                        clientId);
                throw new SharedAttributesValidationException(
                        OAuth2Error.INVALID_GRANT.setDescription(
                                "Invalid redirct_uri claim provided for configured client"));
            }
        } catch (ParseException e) {
            LOGGER.error(
                    "Failed to parse JWT claim set in order to access to the redirect_uri claim");
            throw new SharedAttributesValidationException(
                    OAuth2Error.INVALID_REQUEST_OBJECT.setDescription(
                            "Failed to parse JWT claim set in order to access redirect_uri claim"));
        }
    }
}
