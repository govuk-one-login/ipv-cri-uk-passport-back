package uk.gov.di.ipv.cri.passport.issuecredential;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import uk.gov.di.ipv.cri.common.library.domain.AuditEventContext;
import uk.gov.di.ipv.cri.common.library.domain.AuditEventType;
import uk.gov.di.ipv.cri.common.library.exception.AccessTokenExpiredException;
import uk.gov.di.ipv.cri.common.library.exception.SqsException;
import uk.gov.di.ipv.cri.common.library.service.AuditService;
import uk.gov.di.ipv.cri.common.library.service.SessionService;
import uk.gov.di.ipv.cri.common.library.util.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.cri.common.library.util.KMSSigner;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.passport.library.auditing.AuditEvent;
import uk.gov.di.ipv.cri.passport.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.cri.passport.library.auditing.AuditEventUser;
import uk.gov.di.ipv.cri.passport.library.auditing.AuditExtensions;
import uk.gov.di.ipv.cri.passport.library.auditing.AuditExtensionsVcEvidence;
import uk.gov.di.ipv.cri.passport.library.auditing.AuditRestricted;
import uk.gov.di.ipv.cri.passport.library.auditing.AuditRestrictedVcCredentialSubject;
import uk.gov.di.ipv.cri.passport.library.config.PassportConfigurationService;
import uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.CredentialSubject;
import uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.VerifiableCredential;
import uk.gov.di.ipv.cri.passport.library.helpers.JwtHelper;
import uk.gov.di.ipv.cri.passport.library.helpers.LogHelper;
import uk.gov.di.ipv.cri.passport.library.helpers.RequestHelper;
import uk.gov.di.ipv.cri.passport.library.persistence.item.PassportCheckDao;
import uk.gov.di.ipv.cri.passport.library.service.DcsPassportCheckService;
import uk.gov.di.ipv.cri.passport.library.service.ServiceFactory;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.util.Date;

import static uk.gov.di.ipv.cri.passport.library.config.ConfigurationVariable.MAX_JWT_TTL;
import static uk.gov.di.ipv.cri.passport.library.config.ConfigurationVariable.VERIFIABLE_CREDENTIAL_ISSUER;
import static uk.gov.di.ipv.cri.passport.library.config.ConfigurationVariable.VERIFIABLE_CREDENTIAL_SIGNING_KEY_ID;
import static uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.VerifiableCredentialConstants.VC_CLAIM;

public class IssueCredentialHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final String AUTHORIZATION_HEADER_KEY = "Authorization";
    public static final String PASSPORT_CREDENTIAL_ISSUER = "passport_credential_issuer";

    private final DcsPassportCheckService dcsPassportCheckService;
    private final PassportConfigurationService passportConfigurationService;
    private final AuditService auditService;
    private final SessionService sessionService;
    private final JWSSigner kmsSigner;

    public IssueCredentialHandler(
            DcsPassportCheckService dcsPassportCheckService,
            PassportConfigurationService passportConfigurationService,
            AuditService auditService,
            SessionService sessionService,
            JWSSigner kmsSigner) {
        this.passportConfigurationService = passportConfigurationService;
        this.dcsPassportCheckService = dcsPassportCheckService;
        this.auditService = auditService;
        this.sessionService = sessionService;
        this.kmsSigner = kmsSigner;
    }

    @ExcludeFromGeneratedCoverageReport
    public IssueCredentialHandler()
            throws CertificateException, NoSuchAlgorithmException, IOException,
                    InvalidKeySpecException, KeyStoreException, InvalidKeyException {

        ServiceFactory serviceFactory =
                new ServiceFactory(new ObjectMapper().registerModule(new JavaTimeModule()));
        this.passportConfigurationService = serviceFactory.getPassportConfigurationService();
        this.dcsPassportCheckService = serviceFactory.getDcsPassportCheckService();
        this.auditService = serviceFactory.getAuditService();
        this.sessionService = serviceFactory.getSessionService();

        this.kmsSigner =
                new KMSSigner(
                        passportConfigurationService.getStackSsmParameter(
                                VERIFIABLE_CREDENTIAL_SIGNING_KEY_ID));
    }

    @Override
    @Logging(clearState = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        LogHelper.attachComponentIdToLogs();
        try {
            LOGGER.info("Validating authorization token...");

            var accessToken =
                    AccessToken.parse(
                            RequestHelper.getHeaderByKey(
                                    input.getHeaders(), AUTHORIZATION_HEADER_KEY),
                            AccessTokenType.BEARER);

            var sessionItem = sessionService.getSessionByAccessToken(accessToken);
            LOGGER.info("Extracted session from session store ID {}", sessionItem.getSessionId());

            LogHelper.attachGovukSigninJourneyIdToLogs(sessionItem.getClientSessionId());

            // TODO Revoke needs added to sessionService (sessionService.revokeToken(SessionItem))
            // throwing AccessTokenRevokedException
            // And sessionService methods update to check this when using tokens.
            // Until then, the expiry date change is simulating this.
            // accessTokenService.revokeAccessToken(accessTokenItem.getAccessToken());
            sessionItem.setAccessTokenExpiryDate(Instant.now().toEpochMilli());
            sessionService.updateSession(sessionItem);

            PassportCheckDao passportCheck =
                    dcsPassportCheckService.getDcsPassportCheck(
                            sessionItem.getResponseResourceId());
            LogHelper.attachClientIdToLogs(passportCheck.getClientId());

            VerifiableCredential verifiableCredential =
                    VerifiableCredential.fromPassportCheckDao(passportCheck);

            SignedJWT signedJWT =
                    generateAndSignVerifiableCredentialJwt(verifiableCredential, passportCheck);

            auditService.sendAuditEvent(
                    AuditEventType.VC_ISSUED,
                    new AuditEventContext(input.getHeaders(), sessionItem),
                    new AuditExtensionsVcEvidence(
                            passportConfigurationService.getStackSsmParameter(
                                    VERIFIABLE_CREDENTIAL_ISSUER),
                            verifiableCredential.getEvidence()));

            return ApiGatewayResponseGenerator.proxyJwtResponse(
                    HttpStatus.SC_OK, signedJWT.serialize());
            /*} catch (AccessTokenRevokedException e) {
            // See Revoke TODO
            LOGGER.error(
                    "User credential could not be retrieved. The supplied access token has been revoked");
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    OAuth2Error.ACCESS_DENIED.getHTTPStatusCode(),
                    OAuth2Error.ACCESS_DENIED
                            .appendDescription(" - The supplied access token has been revoked")
                            .toJSONObject());*/
        } catch (AccessTokenExpiredException e) {
            LOGGER.error(
                    "User credential could not be retrieved. The supplied access token expired");
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    OAuth2Error.ACCESS_DENIED.getHTTPStatusCode(),
                    OAuth2Error.ACCESS_DENIED
                            .appendDescription(" - The supplied access token has expired")
                            .toJSONObject());
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
                    uk.gov.di.ipv.cri.passport.library.error.ErrorResponse
                            .FAILED_TO_SEND_AUDIT_MESSAGE_TO_SQS_QUEUE);
        } catch (IllegalArgumentException e) {
            LOGGER.error("Failed to revoke access token after use because: {}", e.getMessage());
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR,
                    uk.gov.di.ipv.cri.passport.library.error.ErrorResponse
                            .FAILED_TO_REVOKE_ACCESS_TOKEN);
        }
    }

    private AuditEvent createAuditEvent(VerifiableCredential vc, AuditEventUser user) {
        CredentialSubject credentialSubject = vc.getCredentialSubject();
        String componentId =
                passportConfigurationService.getStackSsmParameter(VERIFIABLE_CREDENTIAL_ISSUER);
        AuditEventTypes eventType = AuditEventTypes.IPV_PASSPORT_CRI_VC_ISSUED;
        AuditRestricted restricted =
                new AuditRestrictedVcCredentialSubject(
                        credentialSubject.getName(),
                        credentialSubject.getBirthDate(),
                        credentialSubject.getPassport());
        AuditExtensions extensions =
                new AuditExtensionsVcEvidence(
                        passportConfigurationService.getStackSsmParameter(
                                VERIFIABLE_CREDENTIAL_ISSUER),
                        vc.getEvidence());
        return new AuditEvent(eventType, componentId, user, restricted, extensions);
    }

    private SignedJWT generateAndSignVerifiableCredentialJwt(
            VerifiableCredential verifiableCredential, PassportCheckDao passportCheck)
            throws JOSEException {
        Instant now = Instant.now();
        JWTClaimsSet claimsSet =
                new JWTClaimsSet.Builder()
                        .subject(passportCheck.getUserId())
                        .issuer(
                                passportConfigurationService.getStackSsmParameter(
                                        VERIFIABLE_CREDENTIAL_ISSUER))
                        .audience(
                                passportConfigurationService.getClientIssuer(
                                        passportCheck.getClientId()))
                        .notBeforeTime(new Date(now.toEpochMilli()))
                        .expirationTime(
                                new Date(
                                        now.plusSeconds(
                                                        Long.parseLong(
                                                                passportConfigurationService
                                                                        .getStackSsmParameter(
                                                                                MAX_JWT_TTL)))
                                                .toEpochMilli()))
                        .claim(VC_CLAIM, verifiableCredential)
                        .build();

        return JwtHelper.createSignedJwtFromClaimSet(claimsSet, kmsSigner);
    }
}
