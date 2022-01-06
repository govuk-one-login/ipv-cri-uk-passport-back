package uk.gov.di.ipv.cri.passport.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.passport.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.persistence.item.DcsResponseItem;
import uk.gov.di.ipv.cri.passport.service.AuthorizationCodeService;
import uk.gov.di.ipv.cri.passport.service.PassportService;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PassportHandlerTest {

    private final ObjectMapper objectMapper =
            new ObjectMapper().registerModule(new JavaTimeModule());
    private final Map<String, String> validPassportFormData =
            Map.of(
                    "passportNumber", "1234567890",
                    "surname", "Tattsyrup",
                    "forenames", "[Tubbs]",
                    "dateOfBirth", "1984-09-28",
                    "expiryDate", "2024-09-03");

    @Mock Context context;
    @Mock PassportService passportService;
    @Mock AuthorizationCodeService authorizationCodeService;

    private PassportHandler underTest;
    private AuthorizationCode authorizationCode;

    @BeforeEach
    void setUp() {
        authorizationCode = new AuthorizationCode();

        underTest = new PassportHandler(passportService, authorizationCodeService);
    }

    @Test
    void shouldReturn200WithCorrectFormData() throws IOException {
        String dcsResponse = "test dcs response";
        when(passportService.dcsPassportCheck(any(String.class))).thenReturn(dcsResponse);

        DcsResponseItem testDcsResponseItem = new DcsResponseItem();
        testDcsResponseItem.setResourcePayload(dcsResponse);
        testDcsResponseItem.setResourceId(UUID.randomUUID().toString());
        when(passportService.persistDcsResponse(dcsResponse)).thenReturn(testDcsResponseItem);

        when(authorizationCodeService.generateAuthorizationCode()).thenReturn(authorizationCode);

        var event = new APIGatewayProxyRequestEvent();
        Map<String, String> params = new HashMap<>();
        params.put(OAuth2RequestParams.REDIRECT_URI, "http://example.com");
        params.put(OAuth2RequestParams.CLIENT_ID, "12345");
        params.put(OAuth2RequestParams.RESPONSE_TYPE, "code");
        params.put(OAuth2RequestParams.SCOPE, "openid");
        event.setQueryStringParameters(params);
        event.setBody(objectMapper.writeValueAsString(validPassportFormData));

        var response = underTest.handleRequest(event, context);

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldReturnAuthResponseOnSuccessfulOauthRequest() throws IOException {
        String dcsResponse = "test dcs response";
        when(passportService.dcsPassportCheck(any(String.class))).thenReturn(dcsResponse);

        DcsResponseItem testDcsResponseItem = new DcsResponseItem();
        testDcsResponseItem.setResourcePayload(dcsResponse);
        testDcsResponseItem.setResourceId(UUID.randomUUID().toString());
        when(passportService.persistDcsResponse(dcsResponse)).thenReturn(testDcsResponseItem);

        when(authorizationCodeService.generateAuthorizationCode()).thenReturn(authorizationCode);

        var event = new APIGatewayProxyRequestEvent();
        Map<String, String> params = new HashMap<>();
        params.put(OAuth2RequestParams.REDIRECT_URI, "http://example.com");
        params.put(OAuth2RequestParams.CLIENT_ID, "12345");
        params.put(OAuth2RequestParams.RESPONSE_TYPE, "code");
        params.put(OAuth2RequestParams.SCOPE, "openid");
        event.setQueryStringParameters(params);
        event.setBody(objectMapper.writeValueAsString(validPassportFormData));

        var response = underTest.handleRequest(event, context);

        ObjectMapper objectMapper = new ObjectMapper();
        Map<String, Object> responseBody = objectMapper.readValue(response.getBody(), Map.class);
        Map<String, String> authCode = (Map) responseBody.get("code");

        verify(authorizationCodeService)
                .persistAuthorizationCode(
                        authCode.get("value"), testDcsResponseItem.getResourceId());
        assertEquals(authorizationCode.toString(), authCode.get("value"));
    }

    @Test
    void shouldReturn400OnMissingRedirectUriParam() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Map<String, String> params = new HashMap<>();
        params.put(OAuth2RequestParams.CLIENT_ID, "12345");
        params.put(OAuth2RequestParams.RESPONSE_TYPE, "code");
        params.put(OAuth2RequestParams.SCOPE, "openid");
        event.setQueryStringParameters(params);
        event.setBody(objectMapper.writeValueAsString(validPassportFormData));

        var response = underTest.handleRequest(event, context);

        ObjectMapper objectMapper = new ObjectMapper();
        Map responseBody = objectMapper.readValue(response.getBody(), Map.class);

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS.getCode(),
                responseBody.get("code"));
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS.getMessage(),
                responseBody.get("message"));
    }

    @Test
    void shouldReturn400OnMissingClientIdParam() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Map<String, String> params = new HashMap<>();
        params.put(OAuth2RequestParams.REDIRECT_URI, "http://example.com");
        params.put(OAuth2RequestParams.RESPONSE_TYPE, "code");
        params.put(OAuth2RequestParams.SCOPE, "openid");
        event.setQueryStringParameters(params);
        event.setBody(objectMapper.writeValueAsString(validPassportFormData));

        var response = underTest.handleRequest(event, context);

        ObjectMapper objectMapper = new ObjectMapper();
        Map responseBody = objectMapper.readValue(response.getBody(), Map.class);

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS.getCode(),
                responseBody.get("code"));
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS.getMessage(),
                responseBody.get("message"));
    }

    @Test
    void shouldReturn400OnMissingResponseTypeParam() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Map<String, String> params = new HashMap<>();
        params.put(OAuth2RequestParams.REDIRECT_URI, "http://example.com");
        params.put(OAuth2RequestParams.CLIENT_ID, "12345");
        params.put(OAuth2RequestParams.SCOPE, "openid");
        event.setQueryStringParameters(params);
        event.setBody(objectMapper.writeValueAsString(validPassportFormData));

        var response = underTest.handleRequest(event, context);

        ObjectMapper objectMapper = new ObjectMapper();
        Map responseBody = objectMapper.readValue(response.getBody(), Map.class);

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS.getCode(),
                responseBody.get("code"));
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS.getMessage(),
                responseBody.get("message"));
    }

    @Test
    void shouldReturn400OnMissingScopeParam() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Map<String, String> params = new HashMap<>();
        params.put(OAuth2RequestParams.REDIRECT_URI, "http://example.com");
        params.put(OAuth2RequestParams.CLIENT_ID, "12345");
        params.put(OAuth2RequestParams.RESPONSE_TYPE, "code");
        event.setQueryStringParameters(params);
        event.setBody(objectMapper.writeValueAsString(validPassportFormData));

        var response = underTest.handleRequest(event, context);

        ObjectMapper objectMapper = new ObjectMapper();
        Map responseBody = objectMapper.readValue(response.getBody(), Map.class);

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS.getCode(),
                responseBody.get("code"));
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS.getMessage(),
                responseBody.get("message"));
    }

    @Test
    void shouldReturn400OnMissingQueryParameters() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        event.setBody(objectMapper.writeValueAsString(validPassportFormData));

        APIGatewayProxyResponseEvent response = underTest.handleRequest(event, context);

        ObjectMapper objectMapper = new ObjectMapper();
        Map responseBody = objectMapper.readValue(response.getBody(), Map.class);

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.MISSING_QUERY_PARAMETERS.getCode(), responseBody.get("code"));
        assertEquals(
                ErrorResponse.MISSING_QUERY_PARAMETERS.getMessage(), responseBody.get("message"));
    }

    @Test
    void shouldReturn400IfDataIsMissing() throws JsonProcessingException {
        var formFields = validPassportFormData.keySet();
        for (String keyToRemove : formFields) {
            var event = new APIGatewayProxyRequestEvent();
            Map<String, String> params = new HashMap<>();
            params.put(OAuth2RequestParams.REDIRECT_URI, "http://example.com");
            params.put(OAuth2RequestParams.CLIENT_ID, "12345");
            params.put(OAuth2RequestParams.RESPONSE_TYPE, "code");
            params.put(OAuth2RequestParams.SCOPE, "openid");
            event.setQueryStringParameters(params);
            event.setBody(
                    objectMapper.writeValueAsString(
                            new HashMap<>(validPassportFormData).remove(keyToRemove)));

            var response = underTest.handleRequest(event, context);
            var responseBody = objectMapper.readValue(response.getBody(), Map.class);

            assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
            assertEquals(
                    ErrorResponse.FAILED_TO_PARSE_PASSPORT_FORM_DATA.getCode(),
                    responseBody.get("code"));
            assertEquals(
                    ErrorResponse.FAILED_TO_PARSE_PASSPORT_FORM_DATA.getMessage(),
                    responseBody.get("message"));
        }
    }

    @Test
    void shouldReturn400IfDateStringsAreWrongFormat() throws JsonProcessingException {
        var mangledDateInput = new HashMap<>(validPassportFormData);
        mangledDateInput.put("dateOfBirth", "28-09-1984");

        var event = new APIGatewayProxyRequestEvent();
        Map<String, String> params = new HashMap<>();
        params.put(OAuth2RequestParams.REDIRECT_URI, "http://example.com");
        params.put(OAuth2RequestParams.CLIENT_ID, "12345");
        params.put(OAuth2RequestParams.RESPONSE_TYPE, "code");
        params.put(OAuth2RequestParams.SCOPE, "openid");
        event.setQueryStringParameters(params);
        event.setBody(objectMapper.writeValueAsString(mangledDateInput));

        var response = underTest.handleRequest(event, context);
        var responseBody = objectMapper.readValue(response.getBody(), Map.class);

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_PASSPORT_FORM_DATA.getCode(),
                responseBody.get("code"));
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_PASSPORT_FORM_DATA.getMessage(),
                responseBody.get("message"));
    }

    @Test
    void shouldPersistDcsResponse() throws IOException {
        String dcsResponse = "test dcs response payload";
        when(passportService.dcsPassportCheck(any(String.class))).thenReturn(dcsResponse);

        DcsResponseItem testDcsResponseItem = new DcsResponseItem();
        testDcsResponseItem.setResourcePayload(dcsResponse);
        testDcsResponseItem.setResourceId(UUID.randomUUID().toString());
        when(passportService.persistDcsResponse(dcsResponse)).thenReturn(testDcsResponseItem);

        when(authorizationCodeService.generateAuthorizationCode()).thenReturn(authorizationCode);

        var event = new APIGatewayProxyRequestEvent();
        Map<String, String> params = new HashMap<>();
        params.put(OAuth2RequestParams.REDIRECT_URI, "http://example.com");
        params.put(OAuth2RequestParams.CLIENT_ID, "12345");
        params.put(OAuth2RequestParams.RESPONSE_TYPE, "code");
        params.put(OAuth2RequestParams.SCOPE, "openid");
        event.setQueryStringParameters(params);
        event.setBody(objectMapper.writeValueAsString(validPassportFormData));

        underTest.handleRequest(event, context);

        ArgumentCaptor<String> responseArgumentCaptor = ArgumentCaptor.forClass(String.class);
        verify(passportService).persistDcsResponse(responseArgumentCaptor.capture());

        assertEquals(dcsResponse, responseArgumentCaptor.getValue());
    }

    @Test
    void shouldPersistAuthCode() throws IOException {
        String dcsResponse = "test dcs response payload";
        when(passportService.dcsPassportCheck(any(String.class))).thenReturn(dcsResponse);

        DcsResponseItem testDcsResponseItem = new DcsResponseItem();
        testDcsResponseItem.setResourcePayload(dcsResponse);
        testDcsResponseItem.setResourceId(UUID.randomUUID().toString());
        when(passportService.persistDcsResponse(dcsResponse)).thenReturn(testDcsResponseItem);

        when(authorizationCodeService.generateAuthorizationCode()).thenReturn(authorizationCode);

        var event = new APIGatewayProxyRequestEvent();
        Map<String, String> params = new HashMap<>();
        params.put(OAuth2RequestParams.REDIRECT_URI, "http://example.com");
        params.put(OAuth2RequestParams.CLIENT_ID, "12345");
        params.put(OAuth2RequestParams.RESPONSE_TYPE, "code");
        params.put(OAuth2RequestParams.SCOPE, "openid");
        event.setQueryStringParameters(params);
        event.setBody(objectMapper.writeValueAsString(validPassportFormData));

        underTest.handleRequest(event, context);

        ArgumentCaptor<String> authCodeArgumentCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> resourceIdArgumentCaptor = ArgumentCaptor.forClass(String.class);
        verify(authorizationCodeService)
                .persistAuthorizationCode(
                        authCodeArgumentCaptor.capture(), resourceIdArgumentCaptor.capture());

        assertEquals(authorizationCode.toString(), authCodeArgumentCaptor.getValue());
        assertEquals(testDcsResponseItem.getResourceId(), resourceIdArgumentCaptor.getValue());
    }
}
