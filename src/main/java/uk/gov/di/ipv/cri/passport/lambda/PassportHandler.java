package uk.gov.di.ipv.cri.passport.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.apache.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.cri.passport.domain.DcsPayload;
import uk.gov.di.ipv.cri.passport.domain.DcsSignedEncryptedResponse;
import uk.gov.di.ipv.cri.passport.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.cri.passport.persistence.item.DcsResponseItem;
import uk.gov.di.ipv.cri.passport.service.AuthorizationCodeService;
import uk.gov.di.ipv.cri.passport.service.ConfigurationService;
import uk.gov.di.ipv.cri.passport.service.DcsCryptographyService;
import uk.gov.di.ipv.cri.passport.service.PassportService;
import uk.gov.di.ipv.cri.passport.validation.ValidationResult;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

public class PassportHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(PassportHandler.class);

    private static final ObjectMapper objectMapper =
            new ObjectMapper().registerModule(new JavaTimeModule());

    static {
        // Set the default synchronous HTTP client to UrlConnectionHttpClient
        System.setProperty(
                "software.amazon.awssdk.http.service.impl",
                "software.amazon.awssdk.http.urlconnection.UrlConnectionSdkHttpService");
    }

    private final PassportService passportService;
    private final AuthorizationCodeService authorizationCodeService;
    private final ConfigurationService configurationService;
    private final DcsCryptographyService dcsCryptographyService;

    public PassportHandler(
            PassportService passportService,
            AuthorizationCodeService authorizationCodeService,
            ConfigurationService configurationService,
            DcsCryptographyService dcsCryptographyService) {
        this.passportService = passportService;
        this.authorizationCodeService = authorizationCodeService;
        this.configurationService = configurationService;
        this.dcsCryptographyService = dcsCryptographyService;
    }

    public PassportHandler()
            throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException,
                    KeyStoreException, IOException {
        this.passportService = new PassportService();
        this.authorizationCodeService = new AuthorizationCodeService();
        this.configurationService = new ConfigurationService();
        this.dcsCryptographyService = new DcsCryptographyService(configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        Map<String, List<String>> queryStringParameters = getQueryStringParametersAsMap(input);

        try {
            ValidationResult<ErrorResponse> validationResult =
                    validateRequest(queryStringParameters);
            if (!validationResult.isValid()) {
                LOGGER.error("Missing required query parameters for authorisation request");
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        HttpStatus.SC_BAD_REQUEST, validationResult.getError());
            }

            AuthenticationRequest.parse(queryStringParameters);
        } catch (ParseException e) {
            LOGGER.error("Authentication request could not be parsed", e);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_BAD_REQUEST,
                    ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS);
        }
        LOGGER.info("Successfully parsed authentication request");

        DcsPayload dcsPayload;
        try {
            dcsPayload = objectMapper.readValue(input.getBody(), DcsPayload.class);

        } catch (JsonProcessingException e) {
            LOGGER.error("Passport form data could not be parsed", e);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_BAD_REQUEST, ErrorResponse.FAILED_TO_PARSE_PASSPORT_FORM_DATA);
        }

        try {
            JWSObject preparedDcsPayload = dcsCryptographyService.preparePayload(dcsPayload);
            DcsSignedEncryptedResponse response =
                    passportService.dcsPassportCheck(preparedDcsPayload);
            DcsResponseItem responseToPersist = dcsCryptographyService.unwrapDcsResponse(response);
            passportService.persistDcsResponse(responseToPersist);

            AuthorizationCode authorizationCode =
                    authorizationCodeService.generateAuthorizationCode();

            authorizationCodeService.persistAuthorizationCode(
                    authorizationCode.getValue(), responseToPersist.getResourceId());

            Map<String, Identifier> payload = Map.of("code", authorizationCode);

            return ApiGatewayResponseGenerator.proxyJsonResponse(HttpStatus.SC_OK, payload);

        } catch (CertificateException
                | NoSuchAlgorithmException
                | InvalidKeySpecException
                | JOSEException
                | JsonProcessingException e) {
            e.printStackTrace();
        } catch (java.text.ParseException e) {
            e.printStackTrace();
        }

        return ApiGatewayResponseGenerator.proxyJsonResponse(HttpStatus.SC_OK, dcsPayload);
    }

    private Map<String, List<String>> getQueryStringParametersAsMap(
            APIGatewayProxyRequestEvent input) {
        if (input.getQueryStringParameters() != null) {
            return input.getQueryStringParameters().entrySet().stream()
                    .collect(
                            Collectors.toMap(
                                    Map.Entry::getKey, entry -> List.of(entry.getValue())));
        }
        return Collections.emptyMap();
    }

    private ValidationResult<ErrorResponse> validateRequest(
            Map<String, List<String>> queryStringParameters) {
        if (Objects.isNull(queryStringParameters) || queryStringParameters.isEmpty()) {
            return new ValidationResult<>(false, ErrorResponse.MISSING_QUERY_PARAMETERS);
        }

        return ValidationResult.createValidResult();
    }
}
