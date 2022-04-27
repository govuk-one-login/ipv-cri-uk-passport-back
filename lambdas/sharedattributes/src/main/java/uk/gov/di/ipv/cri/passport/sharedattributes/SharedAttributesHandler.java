package uk.gov.di.ipv.cri.passport.sharedattributes;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.library.exceptions.JarValidationException;
import uk.gov.di.ipv.cri.passport.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.cri.passport.library.helpers.RequestHelper;
import uk.gov.di.ipv.cri.passport.library.service.ConfigurationService;
import uk.gov.di.ipv.cri.passport.library.validation.JarValidator;

import java.text.ParseException;
import java.util.Map;

public class SharedAttributesHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    public static final String SHARED_CLAIMS = "shared_claims";

    private final ConfigurationService configurationService;
    private final JarValidator jarValidator;

    private static final Logger LOGGER = LoggerFactory.getLogger(SharedAttributesHandler.class);
    private static final Integer OK = 200;
    private static final Integer BAD_REQUEST = 400;
    private static final String CLIENT_ID = "client_id";

    public SharedAttributesHandler(
            ConfigurationService configurationService, JarValidator jarValidator) {
        this.configurationService = configurationService;
        this.jarValidator = jarValidator;
    }

    @ExcludeFromGeneratedCoverageReport
    public SharedAttributesHandler() {
        this.configurationService = new ConfigurationService();
        this.jarValidator = new JarValidator(configurationService);
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
            SignedJWT signedJWT = decryptRequest(input.getBody());

            JWTClaimsSet claimsSet = jarValidator.validateRequestJwt(signedJWT, clientId);

            Map<String, Object> sharedClaims = claimsSet.getJSONObjectClaim(SHARED_CLAIMS);
            if (sharedClaims == null) {
                LOGGER.error("shared_claim not found in JWT");
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        BAD_REQUEST, ErrorResponse.SHARED_CLAIM_IS_MISSING);
            }

            return ApiGatewayResponseGenerator.proxyJsonResponse(OK, sharedClaims);
        } catch (JarValidationException e) {
            LOGGER.error("JAR validation failed: {}", e.getErrorObject().getDescription());
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    e.getErrorObject().getHTTPStatusCode(), e.getErrorObject().toJSONObject());
        } catch (ParseException e) {
            LOGGER.error("Failed to parse claim set when attempting to retrieve shared_claim");
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    BAD_REQUEST, ErrorResponse.FAILED_TO_PARSE);
        }
    }

    private SignedJWT decryptRequest(String jarString) throws ParseException {
        try {
            JWEObject jweObject = JWEObject.parse(jarString);
            return jarValidator.decryptJWE(jweObject);
        } catch (ParseException e) {
            LOGGER.info("The JAR is not currently encrypted. Skipping the decryption step.");
            return SignedJWT.parse(jarString);
        }
    }
}
