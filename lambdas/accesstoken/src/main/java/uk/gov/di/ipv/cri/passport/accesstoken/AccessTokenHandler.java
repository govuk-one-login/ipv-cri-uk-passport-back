package uk.gov.di.ipv.cri.passport.accesstoken;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import uk.gov.di.ipv.cri.common.library.persistence.item.SessionItem;
import uk.gov.di.ipv.cri.passport.accesstoken.exceptions.ClientAuthenticationException;
import uk.gov.di.ipv.cri.passport.accesstoken.validation.TokenRequestValidator;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.passport.library.config.ConfigurationService;
import uk.gov.di.ipv.cri.passport.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.cri.passport.library.helpers.LogHelper;
import uk.gov.di.ipv.cri.passport.library.service.AccessTokenService;
import uk.gov.di.ipv.cri.passport.library.service.AuthorizationCodeService;
import uk.gov.di.ipv.cri.passport.library.service.ClientAuthJwtIdService;
import uk.gov.di.ipv.cri.passport.library.service.PassportSessionService;
import uk.gov.di.ipv.cri.passport.library.validation.ValidationResult;

import java.util.Objects;

public class AccessTokenHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final AccessTokenService accessTokenService;
    private final AuthorizationCodeService authorizationCodeService;
    private final ConfigurationService configurationService;
    private final TokenRequestValidator tokenRequestValidator;

    private final PassportSessionService passportSessionService;

    public AccessTokenHandler(
            AccessTokenService accessTokenService,
            AuthorizationCodeService authorizationCodeService,
            ConfigurationService configurationService,
            TokenRequestValidator tokenRequestValidator,
            PassportSessionService passportSessionService) {
        this.accessTokenService = accessTokenService;
        this.authorizationCodeService = authorizationCodeService;
        this.configurationService = configurationService;
        this.tokenRequestValidator = tokenRequestValidator;
        this.passportSessionService = passportSessionService;
    }

    @ExcludeFromGeneratedCoverageReport
    public AccessTokenHandler() {
        this.configurationService = new ConfigurationService();
        this.accessTokenService = new AccessTokenService(configurationService);
        this.authorizationCodeService = new AuthorizationCodeService(configurationService);
        this.tokenRequestValidator =
                new TokenRequestValidator(
                        configurationService, new ClientAuthJwtIdService(configurationService));
        this.passportSessionService = new PassportSessionService(configurationService);
    }

    @Override
    @Logging(clearState = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        LogHelper.attachComponentIdToLogs();
        try {
            tokenRequestValidator.authenticateClient(input.getBody());

            AuthorizationCodeGrant authorizationGrant =
                    (AuthorizationCodeGrant)
                            AuthorizationGrant.parse(URLUtils.parseParameters(input.getBody()));
            ValidationResult<ErrorObject> validationResult =
                    accessTokenService.validateAuthorizationGrant(authorizationGrant);
            if (!validationResult.isValid()) {
                ErrorObject error = validationResult.getError();
                LogHelper.logOauthError(
                        "Invalid auth grant received", error.getCode(), error.getDescription());
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        getHttpStatusCodeForErrorResponse(validationResult.getError()),
                        validationResult.getError().toJSONObject());
            }

            SessionItem authorizationCodeItem =
                    authorizationCodeService.getSessionByAuthCode(
                            authorizationGrant.getAuthorizationCode().getValue());

            String authorizationCode = authorizationCodeItem.getAuthorizationCode();
            if (authorizationCode == null) {
                LOGGER.error(
                        "Access Token could not be issued. The supplied authorization code was not found in the database.");
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        OAuth2Error.INVALID_GRANT.getHTTPStatusCode(),
                        OAuth2Error.INVALID_GRANT.toJSONObject());
            }
            LogHelper.attachPassportSessionIdToLogs(authorizationCodeItem.getSessionId().toString());

            LogHelper.attachGovukSigninJourneyIdToLogs(
                    authorizationCodeItem.getClientSessionId());

            if (authorizationCodeItem.getAccessToken() != null) {
                LOGGER.error(
                        "Auth code has been used multiple times. Auth code was exchanged for an access token at: {}",
                        authorizationCodeItem.getAccessTokenExchangedDateTime());

                ErrorObject error = revokeAccessToken(authorizationCodeItem.getAccessToken());
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        error.getHTTPStatusCode(), error.toJSONObject());
            }

            if (authorizationCodeService.isExpired(authorizationCodeItem)) {
                LOGGER.error(
                        "Access Token could not be issued. The supplied authorization code has expired. Created at: {}",
                        authorizationCodeItem.getAuthCodeCreatedDateTime());
                ErrorObject error =
                        OAuth2Error.INVALID_GRANT.setDescription("Authorization code expired");
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        error.getHTTPStatusCode(), error.toJSONObject());
            }

            if (redirectUrlsDoNotMatch(authorizationCodeItem, authorizationGrant)) {
                LOGGER.error(
                        "Redirect URL in token request does not match that received in auth code request. Resource ID: {}",
                        authorizationCodeItem.getSessionId());
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        OAuth2Error.INVALID_GRANT.getHTTPStatusCode(),
                        OAuth2Error.INVALID_GRANT.toJSONObject());
            }

            AccessTokenResponse accessTokenResponse =
                    accessTokenService.generateAccessToken().toSuccessResponse();

            accessTokenService.persistAccessToken(authorizationCodeItem,
                    accessTokenResponse);

            authorizationCodeService.setIssuedAccessToken(
                    authorizationCodeItem,
                    accessTokenResponse.getTokens().getBearerAccessToken().getValue());

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_OK, accessTokenResponse.toJSONObject());
        } catch (ParseException e) {
            LOGGER.error(
                    "Token request could not be parsed: '{}'",
                    e.getErrorObject().getDescription(),
                    e);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    getHttpStatusCodeForErrorResponse(e.getErrorObject()),
                    e.getErrorObject().toJSONObject());
        } catch (ClientAuthenticationException e) {
            LOGGER.error("Client authentication failed: ", e);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    OAuth2Error.INVALID_CLIENT.getHTTPStatusCode(),
                    OAuth2Error.INVALID_CLIENT.toJSONObject());
        }
    }

    private int getHttpStatusCodeForErrorResponse(ErrorObject errorObject) {
        return errorObject.getHTTPStatusCode() > 0
                ? errorObject.getHTTPStatusCode()
                : HttpStatus.SC_BAD_REQUEST;
    }

    private boolean redirectUrlsDoNotMatch(
            SessionItem passportSessionItem, AuthorizationCodeGrant authorizationGrant) {

        if (Objects.isNull(passportSessionItem.getRedirectUri())
                && Objects.isNull(authorizationGrant.getRedirectionURI())) {
            return false;
        }

        if (Objects.isNull(passportSessionItem.getRedirectUri())
                || Objects.isNull(authorizationGrant.getRedirectionURI())) {
            return true;
        }

        return !authorizationGrant
                .getRedirectionURI()
                .toString()
                .equals(passportSessionItem.getRedirectUri().toString());
    }

    private ErrorObject revokeAccessToken(String accessToken) {
        try {
            accessTokenService.revokeAccessToken(accessToken);
            return OAuth2Error.INVALID_GRANT.setDescription(
                    "Authorization code used too many times");
        } catch (IllegalArgumentException e) {
            LOGGER.error("Failed to revoke access token because: {}", e.getMessage());
            return OAuth2Error.INVALID_GRANT.setDescription("Failed to revoke access token");
        }
    }
}
