package uk.gov.di.ipv.cri.passport.issuecredential;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.apache.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.passport.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.VerifiableCredential;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.library.exceptions.SqsException;
import uk.gov.di.ipv.cri.passport.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.cri.passport.library.helpers.JwtHelper;
import uk.gov.di.ipv.cri.passport.library.helpers.KmsSigner;
import uk.gov.di.ipv.cri.passport.library.helpers.RequestHelper;
import uk.gov.di.ipv.cri.passport.library.persistence.item.PassportCheckDao;
import uk.gov.di.ipv.cri.passport.library.service.AccessTokenService;
import uk.gov.di.ipv.cri.passport.library.service.AuditService;
import uk.gov.di.ipv.cri.passport.library.service.ConfigurationService;
import uk.gov.di.ipv.cri.passport.library.service.DcsPassportCheckService;

import java.time.Instant;

import static com.nimbusds.jwt.JWTClaimNames.EXPIRATION_TIME;
import static com.nimbusds.jwt.JWTClaimNames.ISSUER;
import static com.nimbusds.jwt.JWTClaimNames.NOT_BEFORE;
import static com.nimbusds.jwt.JWTClaimNames.SUBJECT;
import static uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.VerifiableCredentialConstants.DI_CONTEXT;
import static uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.VerifiableCredentialConstants.IDENTITY_CHECK_CREDENTIAL_TYPE;
import static uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.VerifiableCredentialConstants.VC_CONTEXT;
import static uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.VerifiableCredentialConstants.VC_TYPE;
import static uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.VerifiableCredentialConstants.VERIFIABLE_CREDENTIAL_TYPE;
import static uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.VerifiableCredentialConstants.W3_BASE_CONTEXT;

public class IssueCredentialHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(IssueCredentialHandler.class);
    private static final String AUTHORIZATION_HEADER_KEY = "Authorization";

    private final DcsPassportCheckService dcsPassportCheckService;
    private final AccessTokenService accessTokenService;
    private final ConfigurationService configurationService;
    private final AuditService auditService;
    private final JWSSigner kmsSigner;

    public IssueCredentialHandler(
            DcsPassportCheckService dcsPassportCheckService,
            AccessTokenService accessTokenService,
            ConfigurationService configurationService,
            AuditService auditService,
            JWSSigner kmsSigner) {
        this.configurationService = configurationService;
        this.dcsPassportCheckService = dcsPassportCheckService;
        this.accessTokenService = accessTokenService;
        this.auditService = auditService;
        this.kmsSigner = kmsSigner;
    }

    @ExcludeFromGeneratedCoverageReport
    public IssueCredentialHandler() {
        this.configurationService = new ConfigurationService();
        this.dcsPassportCheckService = new DcsPassportCheckService(configurationService);
        this.accessTokenService = new AccessTokenService(configurationService);
        this.auditService =
                new AuditService(AuditService.getDefaultSqsClient(), configurationService);
        this.kmsSigner =
                new KmsSigner(configurationService.getVerifiableCredentialKmsSigningKeyId());
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        try {
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

            PassportCheckDao passportCheck =
                    dcsPassportCheckService.getDcsPassportCheck(resourceId);

            VerifiableCredential verifiableCredential =
                    VerifiableCredential.fromPassportCheckDao(passportCheck);

            SignedJWT signedJWT =
                    generateAndSignVerifiableCredentialJwt(
                            verifiableCredential, passportCheck.getUserId());

            auditService.sendAuditEvent(AuditEventTypes.PASSPORT_CREDENTIAL_ISSUED);

            return ApiGatewayResponseGenerator.proxyJwtResponse(
                    HttpStatus.SC_OK, signedJWT.serialize());
        } catch (ParseException e) {
            LOGGER.error("Failed to parse access token");
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    e.getErrorObject().getHTTPStatusCode(), e.getErrorObject().toJSONObject());
        } catch (JOSEException e) {
            LOGGER.error("Failed to sign verifiable credential: '{}'", e.getMessage());
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    OAuth2Error.SERVER_ERROR.getHTTPStatusCode(),
                    OAuth2Error.SERVER_ERROR
                            .appendDescription(" " + e.getMessage())
                            .toJSONObject());
        } catch (SqsException e) {
            LOGGER.error("Failed to send audit event to SQS queue because: {}", e.getMessage());
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_BAD_REQUEST,
                    ErrorResponse.FAILED_TO_SEND_AUDIT_MESSAGE_TO_SQS_QUEUE);
        }
    }

    private SignedJWT generateAndSignVerifiableCredentialJwt(
            VerifiableCredential verifiableCredential, String subject) throws JOSEException {
        Instant now = Instant.now();
        JWTClaimsSet claimsSet =
                new JWTClaimsSet.Builder()
                        .claim(SUBJECT, subject)
                        .claim(ISSUER, configurationService.getVerifiableCredentialIssuer())
                        .claim(NOT_BEFORE, now.getEpochSecond())
                        .claim(
                                EXPIRATION_TIME,
                                now.plusSeconds(configurationService.maxJwtTtl()).getEpochSecond())
                        .claim(VC_CONTEXT, new String[] {W3_BASE_CONTEXT, DI_CONTEXT})
                        .claim(
                                VC_TYPE,
                                new String[] {
                                    VERIFIABLE_CREDENTIAL_TYPE, IDENTITY_CHECK_CREDENTIAL_TYPE
                                })
                        .claim(VC_CLAIM, verifiableCredential)
                        .build();

        return JwtHelper.createSignedJwtFromClaimSet(claimsSet, kmsSigner);
    }
}
