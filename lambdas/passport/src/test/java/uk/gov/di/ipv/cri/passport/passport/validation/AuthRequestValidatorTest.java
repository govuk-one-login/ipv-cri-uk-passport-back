package uk.gov.di.ipv.cri.passport.passport.validation;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.library.service.ConfigurationService;
import uk.gov.di.ipv.cri.passport.library.validation.ValidationResult;
import uk.gov.di.ipv.cri.passport.passport.OAuth2RequestParams;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthRequestValidatorTest {

    @Mock private ConfigurationService mockConfigurationService;

    private static final Map<String, List<String>> VALID_QUERY_STRING_PARAMS =
            Map.of(
                    OAuth2RequestParams.REDIRECT_URI, List.of("http://example.com"),
                    OAuth2RequestParams.CLIENT_ID, List.of("12345"),
                    OAuth2RequestParams.RESPONSE_TYPE, List.of("code"),
                    OAuth2RequestParams.SCOPE, List.of("openid"));

    private AuthRequestValidator validator;

    @BeforeEach
    void setUp() {
        validator = new AuthRequestValidator(mockConfigurationService);
    }

    @Test
    void validateRequestReturnsValidResultForValidRequest() {
        when(mockConfigurationService.getClientRedirectUrls("12345"))
                .thenReturn(List.of("http://example.com"));

        var validationResult = validator.validateRequest(VALID_QUERY_STRING_PARAMS);

        assertTrue(validationResult.isValid());
    }

    @Test
    void validateRequestReturnsErrorResponseForNullParams() {
        var validationResult = validator.validateRequest(null);

        assertFalse(validationResult.isValid());
        assertEquals(
                ErrorResponse.MISSING_QUERY_PARAMETERS.getCode(),
                validationResult.getError().getCode());
        assertEquals(
                ErrorResponse.MISSING_QUERY_PARAMETERS.getMessage(),
                validationResult.getError().getMessage());
    }

    @Test
    void validateRequestReturnsErrorResponseForEmptyParameters() {
        var validationResult = validator.validateRequest(Collections.emptyMap());

        assertFalse(validationResult.isValid());
        assertEquals(
                ErrorResponse.MISSING_QUERY_PARAMETERS.getCode(),
                validationResult.getError().getCode());
        assertEquals(
                ErrorResponse.MISSING_QUERY_PARAMETERS.getMessage(),
                validationResult.getError().getMessage());
    }

    @Test
    void validateRequestReturnsErrorIfMissingParamsForValidatingRedirectUrl() {
        var paramsToTest = List.of(OAuth2RequestParams.REDIRECT_URI, OAuth2RequestParams.CLIENT_ID);
        for (String paramToTest : paramsToTest) {
            var invalidQueryStringParams = new HashMap<>(VALID_QUERY_STRING_PARAMS);
            invalidQueryStringParams.remove(paramToTest);

            ValidationResult<ErrorResponse> validationResult =
                    validator.validateRequest(invalidQueryStringParams);

            assertFalse(validationResult.isValid());
            assertEquals(
                    ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS.getCode(),
                    validationResult.getError().getCode());
            assertEquals(
                    ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS.getMessage(),
                    validationResult.getError().getMessage());
        }
    }

    @Test
    void validateRequestReturnsErrorIfRedirectUrlNotRegistered() {
        List<String> registeredRedirectUrls =
                List.of(
                        "https://wrong.example.com",
                        "https://nope.example.com",
                        "https://whoops.example.com");
        when(mockConfigurationService.getClientRedirectUrls("12345"))
                .thenReturn(registeredRedirectUrls);

        var validationResult = validator.validateRequest(VALID_QUERY_STRING_PARAMS);

        assertFalse(validationResult.isValid());
        assertEquals(
                ErrorResponse.INVALID_REDIRECT_URL.getCode(),
                validationResult.getError().getCode());
        assertEquals(
                ErrorResponse.INVALID_REDIRECT_URL.getMessage(),
                validationResult.getError().getMessage());
    }
}
