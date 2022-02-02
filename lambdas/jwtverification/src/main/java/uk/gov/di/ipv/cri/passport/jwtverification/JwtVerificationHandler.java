package uk.gov.di.ipv.cri.passport.jwtverification;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.cri.passport.library.helpers.RequestHelper;
import uk.gov.di.ipv.cri.passport.library.service.ConfigurationService;

import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Map;

public class JwtVerificationHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final ConfigurationService configurationService;

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtVerificationHandler.class);
    private static final Integer OK = 200;
    private static final Integer BAD_REQUEST = 400;
    private static final String CLIENT_ID = "client_id";

    public JwtVerificationHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
    }

    @ExcludeFromGeneratedCoverageReport
    public JwtVerificationHandler() {
        this.configurationService = new ConfigurationService();
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {

        String clientId = RequestHelper.getHeaderByKey(input.getHeaders(), CLIENT_ID);

        if (StringUtils.isBlank(clientId)) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(BAD_REQUEST, ErrorResponse.MISSING_CLIENT_ID_QUERY_PARAMETER);
        }

        if (input.getBody() == null) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(BAD_REQUEST, ErrorResponse.MISSING_SHARED_ATTRIBUTES_JWT);
        }

        try {
            SignedJWT signedJWT = SignedJWT.parse(input.getBody());
            Certificate clientCert = configurationService.getClientCert(clientId);

            if (isInvalidSignature(signedJWT, clientCert)) {
                LOGGER.error("JWT signature is invalid");
                return ApiGatewayResponseGenerator.proxyJsonResponse(BAD_REQUEST, ErrorResponse.JWT_SIGNATURE_IS_INVALID);
            }

            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            Map<String, Object> claims = claimsSet.toJSONObject();

            return ApiGatewayResponseGenerator.proxyJsonResponse(OK, claims);
        } catch (ParseException e) {
            LOGGER.error("Failed to parse the shared attributes JWT", e);
            return ApiGatewayResponseGenerator.proxyJsonResponse(BAD_REQUEST, ErrorResponse.FAILED_TO_PARSE_SHARED_ATTRIBUTES_JWT);
        } catch (CertificateException | JOSEException e) {
            LOGGER.error("Failed to verify the signature of the JWT", e);
            return ApiGatewayResponseGenerator.proxyJsonResponse(BAD_REQUEST, ErrorResponse.FAILED_TO_VERIFY_SIGNATURE);
        }
    }

    private boolean isInvalidSignature(SignedJWT signedJWT, Certificate clientCertificate)
            throws JOSEException {
        PublicKey publicKey = clientCertificate.getPublicKey();
        RSASSAVerifier rsassaVerifier =
                new RSASSAVerifier(
                        (RSAPublicKey) publicKey);
        return !signedJWT.verify(rsassaVerifier);
    }
}
