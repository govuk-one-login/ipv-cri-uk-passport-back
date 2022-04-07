package uk.gov.di.ipv.cri.passport.sharedattributes;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.cri.passport.library.helpers.JwtHelper;
import uk.gov.di.ipv.cri.passport.library.helpers.RequestHelper;
import uk.gov.di.ipv.cri.passport.library.service.ConfigurationService;

import java.text.ParseException;
import java.util.Map;

public class SharedAttributesHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    public static final String SHARED_CLAIMS = "shared_claims";
    private final ConfigurationService configurationService;

    private static final Logger LOGGER = LoggerFactory.getLogger(SharedAttributesHandler.class);
    private static final Integer OK = 200;
    private static final Integer BAD_REQUEST = 400;
    private static final String CLIENT_ID = "client_id";

    public SharedAttributesHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
    }

    @ExcludeFromGeneratedCoverageReport
    public SharedAttributesHandler() {
        this.configurationService = new ConfigurationService();
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {

        String clientId = RequestHelper.getHeaderByKey(input.getHeaders(), CLIENT_ID);

        if (StringUtils.isBlank(clientId)) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    BAD_REQUEST, ErrorResponse.MISSING_CLIENT_ID_QUERY_PARAMETER);
        }

        if (input.getBody() == null) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    BAD_REQUEST, ErrorResponse.MISSING_SHARED_ATTRIBUTES_JWT);
        }

        try {
            SignedJWT signedJWT = SignedJWT.parse(input.getBody());

            if (isInvalidSignature(signedJWT, clientId)) {
                LOGGER.error("JWT signature is invalid");
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        BAD_REQUEST, ErrorResponse.JWT_SIGNATURE_IS_INVALID);
            }

            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            Map<String, Object> sharedClaims = claimsSet.getJSONObjectClaim(SHARED_CLAIMS);

            if (sharedClaims == null) {
                LOGGER.error("shared_claim not found in JWT");
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        BAD_REQUEST, ErrorResponse.SHARED_CLAIM_IS_MISSING);
            }

            return ApiGatewayResponseGenerator.proxyJsonResponse(OK, sharedClaims);
        } catch (ParseException e) {
            LOGGER.error("Failed to parse", e);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    BAD_REQUEST, ErrorResponse.FAILED_TO_PARSE);
        } catch (JOSEException e) {
            LOGGER.error("Failed to verify the signature of the JWT", e);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    BAD_REQUEST, ErrorResponse.FAILED_TO_VERIFY_SIGNATURE);
        }
    }

    private boolean isInvalidSignature(SignedJWT signedJWT, String clientId)
            throws JOSEException, ParseException {
        SignedJWT concatSignatureJwt;
        if (JwtHelper.signatureIsDerFormat(signedJWT)) {
            concatSignatureJwt = JwtHelper.transcodeSignature(signedJWT);
        } else {
            concatSignatureJwt = signedJWT;
        }
        return !concatSignatureJwt.verify(
                new ECDSAVerifier(configurationService.getClientSigningPublicJwk(clientId)));
    }
}
