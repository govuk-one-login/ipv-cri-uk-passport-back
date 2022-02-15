package uk.gov.di.ipv.cri.passport.passport.validation;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.library.service.ConfigurationService;
import uk.gov.di.ipv.cri.passport.library.validation.ValidationResult;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

public class AuthRequestValidator {

    public static final String CLIENT_ID_PARAM = "client_id";
    public static final String REDIRECT_URI_PARAM = "redirect_uri";
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthRequestValidator.class);

    private final ConfigurationService configurationService;

    public AuthRequestValidator(ConfigurationService configurationService) {
        this.configurationService = configurationService;
    }

    public ValidationResult<ErrorResponse> validateRequest(
            Map<String, List<String>> queryStringParameters) {
        if (queryStringParamsMissing(queryStringParameters)) {
            LOGGER.error("Missing required query parameters for authorisation request");
            return new ValidationResult<>(false, ErrorResponse.MISSING_QUERY_PARAMETERS);
        }

        var redirectErrorResult = validateRedirectUrl(queryStringParameters);
        if (redirectErrorResult.isPresent()) {
            return new ValidationResult<>(false, redirectErrorResult.get());
        }

        var authParamsErrorResult = validateQueryStringParams(queryStringParameters);
        if (authParamsErrorResult.isPresent()) {
            return new ValidationResult<>(false, authParamsErrorResult.get());
        }

        return ValidationResult.createValidResult();
    }

    private boolean queryStringParamsMissing(Map<String, List<String>> queryStringParameters) {
        return Objects.isNull(queryStringParameters) || queryStringParameters.isEmpty();
    }

    private Optional<ErrorResponse> validateRedirectUrl(
            Map<String, List<String>> queryStringParameters) {
        try {
            String redirectUrl =
                    getOnlyValueOrThrow(
                            queryStringParameters.getOrDefault(REDIRECT_URI_PARAM, List.of()));
            String clientId =
                    getOnlyValueOrThrow(
                            queryStringParameters.getOrDefault(CLIENT_ID_PARAM, List.of()));
            List<String> clientRedirectUrls = configurationService.getClientRedirectUrls(clientId);

            if (!clientRedirectUrls.contains(redirectUrl)) {
                LOGGER.error("Invalid redirect URL for client_id {}: '{}'", clientId, redirectUrl);
                return Optional.of(ErrorResponse.INVALID_REDIRECT_URL);
            }
            return Optional.empty();
        } catch (IllegalArgumentException e) {
            LOGGER.error(e.getMessage());
            return Optional.of(ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS);
        }
    }

    private Optional<ErrorResponse> validateQueryStringParams(
            Map<String, List<String>> queryStringParameters) {
        try {
            AuthenticationRequest.parse(queryStringParameters);
            return Optional.empty();
        } catch (ParseException e) {
            LOGGER.error(("Failed to parse oauth query string parameters: " + e.getMessage()));
            return Optional.of(ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS);
        }
    }

    private String getOnlyValueOrThrow(List<String> container) {
        if (container.size() != 1) {
            throw new IllegalArgumentException(
                    String.format("Parameter must have exactly one value: %s", container));
        }
        return container.get(0);
    }
}
