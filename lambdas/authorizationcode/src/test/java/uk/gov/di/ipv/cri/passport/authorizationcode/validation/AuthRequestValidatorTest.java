package uk.gov.di.ipv.cri.passport.authorizationcode.validation;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.passport.authorizationcode.OAuth2RequestParams;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.library.service.ConfigurationService;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

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

        var validationResult = validator.validateRequest(VALID_QUERY_STRING_PARAMS, "test-user-id");

        assertFalse(validationResult.isPresent());
    }

    @Test
    void validateRequestReturnsErrorResponseForNullParams() {
        var validationResult = validator.validateRequest(null, "test-user-id");

        assertTrue(validationResult.isPresent());
        assertEquals(
                ErrorResponse.MISSING_QUERY_PARAMETERS.getCode(), validationResult.get().getCode());
        assertEquals(
                ErrorResponse.MISSING_QUERY_PARAMETERS.getMessage(),
                validationResult.get().getMessage());
    }

    @Test
    void validateRequestReturnsErrorResponseForEmptyParameters() {
        var validationResult = validator.validateRequest(Collections.emptyMap(), "test-user-id");

        assertTrue(validationResult.isPresent());
        assertEquals(
                ErrorResponse.MISSING_QUERY_PARAMETERS.getCode(), validationResult.get().getCode());
        assertEquals(
                ErrorResponse.MISSING_QUERY_PARAMETERS.getMessage(),
                validationResult.get().getMessage());
    }

    @Test
    void validateRequestReturnsErrorIfMissingParamsForValidatingRedirectUrl() {
        var paramsToTest = List.of(OAuth2RequestParams.REDIRECT_URI, OAuth2RequestParams.CLIENT_ID);
        for (String paramToTest : paramsToTest) {
            var invalidQueryStringParams = new HashMap<>(VALID_QUERY_STRING_PARAMS);
            invalidQueryStringParams.remove(paramToTest);

            Optional<ErrorResponse> validationResult =
                    validator.validateRequest(invalidQueryStringParams, "test-user-id");

            assertTrue(validationResult.isPresent());
            assertEquals(
                    ErrorResponse.INVALID_REQUEST_PARAM.getCode(),
                    validationResult.get().getCode());
            assertEquals(
                    ErrorResponse.INVALID_REQUEST_PARAM.getMessage(),
                    validationResult.get().getMessage());
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

        var validationResult = validator.validateRequest(VALID_QUERY_STRING_PARAMS, "test-user-id");

        assertTrue(validationResult.isPresent());
        assertEquals(
                ErrorResponse.INVALID_REDIRECT_URL.getCode(), validationResult.get().getCode());
        assertEquals(
                ErrorResponse.INVALID_REDIRECT_URL.getMessage(),
                validationResult.get().getMessage());
    }

    @Test
    void validateRequestReturnsErrorIfMissingUserId() {
        var validationResult = validator.validateRequest(VALID_QUERY_STRING_PARAMS, null);

        assertTrue(validationResult.isPresent());
        assertEquals(
                ErrorResponse.MISSING_USER_ID_HEADER.getCode(), validationResult.get().getCode());
        assertEquals(
                ErrorResponse.MISSING_USER_ID_HEADER.getMessage(),
                validationResult.get().getMessage());
    }
}
