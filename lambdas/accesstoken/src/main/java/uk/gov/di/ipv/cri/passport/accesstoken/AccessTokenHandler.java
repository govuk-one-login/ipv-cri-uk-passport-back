package uk.gov.di.ipv.cri.passport.accesstoken;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import uk.gov.di.ipv.cri.passport.accesstoken.exceptions.ClientAuthenticationException;
import uk.gov.di.ipv.cri.passport.accesstoken.validation.TokenRequestValidator;
import uk.gov.di.ipv.cri.passport.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.passport.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.cri.passport.library.helpers.LogHelper;
import uk.gov.di.ipv.cri.passport.library.persistence.item.AuthorizationCodeItem;
import uk.gov.di.ipv.cri.passport.library.service.AccessTokenService;
import uk.gov.di.ipv.cri.passport.library.service.AuthorizationCodeService;
import uk.gov.di.ipv.cri.passport.library.service.ConfigurationService;
import uk.gov.di.ipv.cri.passport.library.validation.ValidationResult;

import java.net.URI;
import java.util.Objects;

public class AccessTokenHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final AccessTokenService accessTokenService;
    private final AuthorizationCodeService authorizationCodeService;
    private final ConfigurationService configurationService;
    private final TokenRequestValidator tokenRequestValidator;

    public AccessTokenHandler(
            AccessTokenService accessTokenService,
            AuthorizationCodeService authorizationCodeService,
            ConfigurationService configurationService,
            TokenRequestValidator tokenRequestValidator) {
        this.accessTokenService = accessTokenService;
        this.authorizationCodeService = authorizationCodeService;
        this.configurationService = configurationService;
        this.tokenRequestValidator = tokenRequestValidator;
    }

    @ExcludeFromGeneratedCoverageReport
    public AccessTokenHandler() {
        this.configurationService = new ConfigurationService();
        this.accessTokenService = new AccessTokenService(configurationService);
        this.authorizationCodeService = new AuthorizationCodeService(configurationService);
        this.tokenRequestValidator = new TokenRequestValidator(configurationService);
    }

    @Override
    @Logging(clearState = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        LogHelper.attachComponentIdToLogs();
        try {
            String requestBody = input.getBody();
            tokenRequestValidator.authenticateClient(requestBody);

            TokenRequest tokenRequest = createTokenRequest(requestBody);

            ValidationResult<ErrorObject> validationResult =
                    accessTokenService.validateTokenRequest(tokenRequest);
            if (!validationResult.isValid()) {
                LOGGER.error(
                        "Invalid access token request, error description: {}",
                        validationResult.getError().getDescription());
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        getHttpStatusCodeForErrorResponse(validationResult.getError()),
                        validationResult.getError().toJSONObject());
            }

            AuthorizationCodeGrant authorizationCodeGrant =
                    (AuthorizationCodeGrant) tokenRequest.getAuthorizationGrant();

            AuthorizationCodeItem authorizationCodeItem =
                    authorizationCodeService.getAuthCodeItem(
                            authorizationCodeGrant.getAuthorizationCode().getValue());

            if (authorizationCodeItem == null) {
                LOGGER.error(
                        "Access Token could not be issued. The supplied authorization code was not found in the database.");
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        OAuth2Error.INVALID_GRANT.getHTTPStatusCode(),
                        OAuth2Error.INVALID_GRANT.toJSONObject());
            }
            LogHelper.attachPassportSessionIdToLogs(authorizationCodeItem.getPassportSessionId());

            if (authorizationCodeItem.getIssuedAccessToken() != null) {
                LOGGER.error(
                        "Auth code has been used multiple times. Auth code was exchanged for an access token at: {}",
                        authorizationCodeItem.getExchangeDateTime());

                ErrorObject error = revokeAccessToken(authorizationCodeItem.getIssuedAccessToken());
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        error.getHTTPStatusCode(), error.toJSONObject());
            }

            if (authorizationCodeService.isExpired(authorizationCodeItem)) {
                LOGGER.error(
                        "Access Token could not be issued. The supplied authorization code has expired. Created at: {}",
                        authorizationCodeItem.getCreationDateTime());
                ErrorObject error =
                        OAuth2Error.INVALID_GRANT.setDescription("Authorization code expired");
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        error.getHTTPStatusCode(), error.toJSONObject());
            }

            if (redirectUrlsDoNotMatch(authorizationCodeItem, authorizationCodeGrant)) {
                LOGGER.error(
                        "Redirect URL in token request does not match that received in auth code request. Resource ID: {}",
                        authorizationCodeItem.getResourceId());
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        OAuth2Error.INVALID_REQUEST.getHTTPStatusCode(),
                        OAuth2Error.INVALID_REQUEST.toJSONObject());
            }

            TokenResponse tokenResponse = accessTokenService.generateAccessToken(tokenRequest);
            AccessTokenResponse accessTokenResponse = tokenResponse.toSuccessResponse();

            accessTokenService.persistAccessToken(
                    accessTokenResponse,
                    authorizationCodeItem.getResourceId(),
                    authorizationCodeItem.getPassportSessionId());

            authorizationCodeService.setIssuedAccessToken(
                    authorizationCodeItem.getAuthCode(),
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

    private TokenRequest createTokenRequest(String requestBody) throws ParseException {
        // The URI is not needed/consumed in the resultant TokenRequest
        // therefore any value can be passed here to ensure the parse method
        // successfully materialises a TokenRequest
        URI arbitraryUri = URI.create("https://gds");
        HTTPRequest request = new HTTPRequest(HTTPRequest.Method.POST, arbitraryUri);
        request.setQuery(requestBody);
        request.setContentType(ContentType.APPLICATION_URLENCODED.getType());
        return TokenRequest.parse(request);
    }

    private int getHttpStatusCodeForErrorResponse(ErrorObject errorObject) {
        return errorObject.getHTTPStatusCode() > 0
                ? errorObject.getHTTPStatusCode()
                : HttpStatus.SC_BAD_REQUEST;
    }

    private boolean redirectUrlsDoNotMatch(
            AuthorizationCodeItem authorizationCodeItem,
            AuthorizationCodeGrant authorizationGrant) {

        if (Objects.isNull(authorizationCodeItem.getRedirectUrl())
                && Objects.isNull(authorizationGrant.getRedirectionURI())) {
            return false;
        }

        if (Objects.isNull(authorizationCodeItem.getRedirectUrl())
                || Objects.isNull(authorizationGrant.getRedirectionURI())) {
            return true;
        }

        return !authorizationGrant
                .getRedirectionURI()
                .toString()
                .equals(authorizationCodeItem.getRedirectUrl());
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
