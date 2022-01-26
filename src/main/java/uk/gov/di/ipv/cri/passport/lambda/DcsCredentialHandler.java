package uk.gov.di.ipv.cri.passport.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.apache.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.cri.passport.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.passport.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.cri.passport.helpers.RequestHelper;
import uk.gov.di.ipv.cri.passport.persistence.item.PassportCheckDao;
import uk.gov.di.ipv.cri.passport.service.AccessTokenService;
import uk.gov.di.ipv.cri.passport.service.DcsCredentialService;

import java.util.Map;

public class DcsCredentialHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(DcsCredentialHandler.class);
    private static final String AUTHORIZATION_HEADER_KEY = "Authorization";
    private static final String ATTRIBUTES_PARAM = "attributes";

    private final DcsCredentialService dcsCredentialService;
    private final AccessTokenService accessTokenService;

    static {
        // Set the default synchronous HTTP client to UrlConnectionHttpClient
        System.setProperty(
                "software.amazon.awssdk.http.service.impl",
                "software.amazon.awssdk.http.urlconnection.UrlConnectionSdkHttpService");
    }

    public DcsCredentialHandler(
            DcsCredentialService dcsCredentialService, AccessTokenService accessTokenService) {
        this.dcsCredentialService = dcsCredentialService;
        this.accessTokenService = accessTokenService;
    }

    @ExcludeFromGeneratedCoverageReport
    public DcsCredentialHandler() {
        this.dcsCredentialService = new DcsCredentialService();
        this.accessTokenService = new AccessTokenService();
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

            PassportCheckDao credential = dcsCredentialService.getDcsCredential(resourceId);

            Map<String, Object> credentialMap = Map.of(ATTRIBUTES_PARAM, credential);

            return ApiGatewayResponseGenerator.proxyJsonResponse(HttpStatus.SC_OK, credentialMap);
        } catch (ParseException e) {
            LOGGER.error("Failed to parse access token");
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    e.getErrorObject().getHTTPStatusCode(), e.getErrorObject().toJSONObject());
        }
    }
}
