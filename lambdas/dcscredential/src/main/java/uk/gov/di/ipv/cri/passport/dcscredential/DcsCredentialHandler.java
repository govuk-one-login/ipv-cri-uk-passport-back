package uk.gov.di.ipv.cri.passport.dcscredential;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.apache.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.cri.passport.dcscredential.domain.PassportCredentialIssuerResponse;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.passport.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.cri.passport.library.helpers.KmsSigner;
import uk.gov.di.ipv.cri.passport.library.helpers.RequestHelper;
import uk.gov.di.ipv.cri.passport.library.persistence.item.PassportCheckDao;
import uk.gov.di.ipv.cri.passport.library.service.AccessTokenService;
import uk.gov.di.ipv.cri.passport.library.service.ConfigurationService;
import uk.gov.di.ipv.cri.passport.library.service.DcsCredentialService;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class DcsCredentialHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(DcsCredentialHandler.class);
    private static final String AUTHORIZATION_HEADER_KEY = "Authorization";
    private static final String IPV_SESSION_ID_HEADER_KEY = "ipv-session-id";

    private final DcsCredentialService dcsCredentialService;
    private final AccessTokenService accessTokenService;
    private final ConfigurationService configurationService;

    public DcsCredentialHandler(
            DcsCredentialService dcsCredentialService,
            AccessTokenService accessTokenService,
            ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.dcsCredentialService = dcsCredentialService;
        this.accessTokenService = accessTokenService;
    }

    @ExcludeFromGeneratedCoverageReport
    public DcsCredentialHandler() {
        this.configurationService = new ConfigurationService();
        this.dcsCredentialService = new DcsCredentialService(configurationService);
        this.accessTokenService = new AccessTokenService(configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        try {
            String ipvSessionId = RequestHelper.getHeaderByKey(input.getHeaders(), IPV_SESSION_ID_HEADER_KEY);

            String accessTokenString =
                    RequestHelper.getHeaderByKey(input.getHeaders(), AUTHORIZATION_HEADER_KEY);

            // Performs validation on header value and throws a ParseException if invalid
            AccessToken.parse(accessTokenString);

            String resourceId = accessTokenService.getResourceIdByAccessToken(accessTokenString);

            if (StringUtils.isBlank(resourceId)) {
                LOGGER.error(
                        "User credential could not be retrieved. The supplied access token was not found in the database.");
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        OAuth2Error.ACCESS_DENIED.getHTTPStatusCode(),
                        OAuth2Error.ACCESS_DENIED
                                .appendDescription(
                                        " - The supplied access token was not found in the database")
                                .toJSONObject());
            }

            PassportCheckDao credential = dcsCredentialService.getDcsCredential(resourceId);

            PassportCredentialIssuerResponse passportCredentialIssuerResponse =
                    PassportCredentialIssuerResponse.fromPassportCheckDao(credential);

            SignedJWT signedJWT = generateVerifiedCredential(credential, ipvSessionId);

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_OK, Map.of("verifiableCredential", signedJWT.serialize()));
//                HttpStatus.SC_OK, passportCredentialIssuerResponse);
        } catch (ParseException e) {
            LOGGER.error("Failed to parse access token");
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    e.getErrorObject().getHTTPStatusCode(), e.getErrorObject().toJSONObject());
        } catch (JOSEException e) {
            LOGGER.error("Failed to generate Verified Credential");
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_BAD_REQUEST, "something_went_wrong");
        }
    }


    private SignedJWT generateVerifiedCredential(PassportCheckDao credential, String ipvSessionId) throws JOSEException {
        JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).build();

        Map<String, Object> vc = new LinkedHashMap<>();
        vc.put("@context", new String[] {"https://www.w3.org/2018/credentials/v1", "https://vocab.london.cloudapps.digital/contexts/identity-v1.jsonld"});
        vc.put("type", new String[] {"VerifiableCredential", "IdentityCheckCredential"});

        Map<String, Object> credentialSubject = new LinkedHashMap<>();

        List<Map<String, String>> nameParts = new ArrayList<>();
        for (String forename: credential.getAttributes().getForenames()) {
            nameParts.add(Map.of("value", forename, "type", "GivenName"));
        }
        nameParts.add(Map.of("value", credential.getAttributes().getSurname(), "type", "FamilyName"));
        credentialSubject.put("name", List.of(Map.of("nameParts", nameParts)));

        credentialSubject.put("birthDate", List.of(Map.of("value", credential.getAttributes().getDateOfBirth().toString())));

        credentialSubject.put("expiryDate", Map.of("value", credential.getAttributes().getExpiryDate().toString()));

        credentialSubject.put("passportNumber", Map.of("value", credential.getAttributes().getPassportNumber()));

        vc.put("credentialSubject", credentialSubject);

        vc.put("evidence", List.of(
                Map.of(
                        "type", "PassportCheck",
                        "strength", credential.getGpg45Score().getEvidence().getStrength(),
                        "validity", credential.getGpg45Score().getEvidence().getValidity())));

        Instant now = Instant.now();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("sub", String.format("urn:uuid:%s", ipvSessionId))
                .claim("iss", "https://development-di-ipv-cri-uk-passport-front.london.cloudapps.digital/")
                .claim("nbf", now.getEpochSecond())
                .claim("exp", now.plusSeconds(60 * 60 * 24 * 90).getEpochSecond())
                .claim("vc", vc)
                .build();

        SignedJWT signedJWT = new SignedJWT(jwsHeader, claimsSet);
        signedJWT.sign(new KmsSigner(configurationService.getSharedAttributesSigningKeyId()));

        return signedJWT;
    }
}
