package uk.gov.di.ipv.cri.passport.jwtauthorizationrequest;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.apache.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.passport.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.cri.passport.library.domain.AuthParams;
import uk.gov.di.ipv.cri.passport.library.domain.JarResponse;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.library.error.RedirectErrorResponse;
import uk.gov.di.ipv.cri.passport.library.exceptions.JarValidationException;
import uk.gov.di.ipv.cri.passport.library.exceptions.RecoverableJarValidationException;
import uk.gov.di.ipv.cri.passport.library.exceptions.SqsException;
import uk.gov.di.ipv.cri.passport.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.cri.passport.library.helpers.RequestHelper;
import uk.gov.di.ipv.cri.passport.library.service.AuditService;
import uk.gov.di.ipv.cri.passport.library.service.ConfigurationService;
import uk.gov.di.ipv.cri.passport.library.service.KmsRsaDecrypter;
import uk.gov.di.ipv.cri.passport.library.validation.JarValidator;

import java.text.ParseException;

public class JwtAuthorizationRequestHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final ConfigurationService configurationService;
    private final KmsRsaDecrypter kmsRsaDecrypter;
    private final JarValidator jarValidator;
    private final AuditService auditService;

    private static final Logger LOGGER =
            LoggerFactory.getLogger(JwtAuthorizationRequestHandler.class);
    private static final Integer OK = 200;
    private static final Integer BAD_REQUEST = 400;
    private static final String RESPONSE_TYPE = "response_type";
    private static final String CLIENT_ID = "client_id";
    private static final String STATE = "state";
    private static final String REDIRECT_URI = "redirect_uri";
    private static final String SHARED_CLAIMS = "shared_claims";

    public JwtAuthorizationRequestHandler(
            ConfigurationService configurationService,
            KmsRsaDecrypter kmsRsaDecrypter,
            JarValidator jarValidator,
            AuditService auditService) {
        this.configurationService = configurationService;
        this.kmsRsaDecrypter = kmsRsaDecrypter;
        this.jarValidator = jarValidator;
        this.auditService = auditService;
    }

    @ExcludeFromGeneratedCoverageReport
    public JwtAuthorizationRequestHandler() {
        this.configurationService = new ConfigurationService();
        this.kmsRsaDecrypter = new KmsRsaDecrypter(configurationService.getJarKmsEncryptionKeyId());
        this.jarValidator = new JarValidator(kmsRsaDecrypter, configurationService);
        this.auditService =
                new AuditService(AuditService.getDefaultSqsClient(), configurationService);
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
            this.auditService.sendAuditEvent(AuditEventTypes.IPV_PASSPORT_CRI_START);

            SignedJWT signedJWT = decryptRequest(input.getBody());

            JWTClaimsSet claimsSet = jarValidator.validateRequestJwt(signedJWT, clientId);

            JarResponse response = generateJarResponse(claimsSet);

            return ApiGatewayResponseGenerator.proxyJsonResponse(OK, response);
        } catch (RecoverableJarValidationException e) {
            LOGGER.error("JAR validation failed: {}", e.getErrorObject().getDescription());
            RedirectErrorResponse errorResponse =
                    new RedirectErrorResponse(
                            e.getRedirectUri(), e.getErrorObject().toJSONObject());
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    e.getErrorObject().getHTTPStatusCode(), errorResponse);
        } catch (JarValidationException e) {
            LOGGER.error("JAR validation failed: {}", e.getErrorObject().getDescription());
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    e.getErrorObject().getHTTPStatusCode(), e.getErrorObject().toJSONObject());
        } catch (ParseException e) {
            LOGGER.error("Failed to parse claim set when attempting to retrieve JAR claims");
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    BAD_REQUEST, ErrorResponse.FAILED_TO_PARSE);
        } catch (SqsException e) {
            LOGGER.error("Failed to send audit event to SQS queue because: {}", e.getMessage());
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_BAD_REQUEST,
                    ErrorResponse.FAILED_TO_SEND_AUDIT_MESSAGE_TO_SQS_QUEUE);
        }
    }

    private SignedJWT decryptRequest(String jarString)
            throws ParseException, JarValidationException {
        try {
            JWEObject jweObject = JWEObject.parse(jarString);
            return jarValidator.decryptJWE(jweObject);
        } catch (ParseException e) {
            LOGGER.info("The JAR is not currently encrypted. Skipping the decryption step.");
            return SignedJWT.parse(jarString);
        }
    }

    private JarResponse generateJarResponse(JWTClaimsSet claimsSet) throws ParseException {
        AuthParams authParams =
                new AuthParams(
                        claimsSet.getStringClaim(RESPONSE_TYPE),
                        claimsSet.getStringClaim(CLIENT_ID),
                        claimsSet.getStringClaim(STATE),
                        claimsSet.getStringClaim(REDIRECT_URI));

        return new JarResponse(
                authParams, claimsSet.getSubject(), claimsSet.getJSONObjectClaim(SHARED_CLAIMS));
    }
}
