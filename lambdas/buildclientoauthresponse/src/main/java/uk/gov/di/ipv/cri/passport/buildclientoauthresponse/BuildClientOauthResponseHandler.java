package uk.gov.di.ipv.cri.passport.buildclientoauthresponse;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.apache.http.HttpStatus;
import org.apache.http.client.utils.URIBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import uk.gov.di.ipv.cri.passport.buildclientoauthresponse.domain.ClientDetails;
import uk.gov.di.ipv.cri.passport.buildclientoauthresponse.domain.ClientResponse;
import uk.gov.di.ipv.cri.passport.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.cri.passport.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.cri.passport.library.exceptions.SqsException;
import uk.gov.di.ipv.cri.passport.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.cri.passport.library.helpers.LogHelper;
import uk.gov.di.ipv.cri.passport.library.helpers.RequestHelper;
import uk.gov.di.ipv.cri.passport.library.persistence.item.PassportSessionItem;
import uk.gov.di.ipv.cri.passport.library.service.AuditService;
import uk.gov.di.ipv.cri.passport.library.service.AuthorizationCodeService;
import uk.gov.di.ipv.cri.passport.library.service.ConfigurationService;
import uk.gov.di.ipv.cri.passport.library.service.PassportSessionService;

import java.net.URISyntaxException;

public class BuildClientOauthResponseHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOGGER = LogManager.getLogger();

    private AuthorizationCodeService authorizationCodeService;
    private PassportSessionService passportSessionService;
    private AuditService auditService;
    private ConfigurationService configurationService;

    public BuildClientOauthResponseHandler(
            AuthorizationCodeService authorizationCodeService,
            PassportSessionService passportSessionService,
            AuditService auditService,
            ConfigurationService configurationService) {
        this.authorizationCodeService = authorizationCodeService;
        this.passportSessionService = passportSessionService;
        this.auditService = auditService;
        this.configurationService = configurationService;
    }

    public BuildClientOauthResponseHandler() {
        this.configurationService = new ConfigurationService();
        this.authorizationCodeService = new AuthorizationCodeService(configurationService);
        this.passportSessionService = new PassportSessionService(configurationService);
        this.auditService =
                new AuditService(AuditService.getDefaultSqsClient(), configurationService);
    }

    @Override
    @Logging(clearState = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        LogHelper.attachComponentIdToLogs();

        try {
            String passportSessionId = RequestHelper.getPassportSessionId(input);

            PassportSessionItem passportSessionItem =
                    passportSessionService.getPassportSession(passportSessionId);

            AuthorizationCode authorizationCode =
                    authorizationCodeService.generateAuthorizationCode();

            authorizationCodeService.persistAuthorizationCode(
                    authorizationCode.getValue(), passportSessionId);

            ClientResponse clientResponse =
                    generateClientSuccessResponse(
                            passportSessionItem, authorizationCode.getValue());

            auditService.sendAuditEvent(AuditEventTypes.IPV_PASSPORT_CRI_END);

            return ApiGatewayResponseGenerator.proxyJsonResponse(HttpStatus.SC_OK, clientResponse);
        } catch (HttpResponseExceptionWithErrorBody e) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    e.getStatusCode(), e.getErrorResponse());
        } catch (URISyntaxException e) {
            LOGGER.error("Failed to construct redirect uri because: {}", e.getMessage());
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR, e.getMessage());
        } catch (SqsException e) {
            ErrorObject error = OAuth2Error.SERVER_ERROR.setDescription(e.getMessage());

            LogHelper.logOauthError(
                    "Failed to send message to aws SQS audit event queue",
                    error.getCode(),
                    error.getDescription());

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_BAD_REQUEST, error.toJSONObject());
        }
    }

    private ClientResponse generateClientSuccessResponse(
            PassportSessionItem passportSessionItem, String authorizationCode)
            throws URISyntaxException {
        URIBuilder redirectUri =
                new URIBuilder(
                                passportSessionItem
                                        .getJarOauthParams()
                                        .getAuthParams()
                                        .getRedirectUri())
                        .addParameter("code", authorizationCode);

        if (StringUtils.isNotBlank(
                passportSessionItem.getJarOauthParams().getAuthParams().getState())) {
            redirectUri.addParameter(
                    "state", passportSessionItem.getJarOauthParams().getAuthParams().getState());
        }

        return new ClientResponse(new ClientDetails(redirectUri.build().toString()));
    }
}
