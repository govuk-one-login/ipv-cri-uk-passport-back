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
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.apache.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.cri.passport.domain.DcsPayload;
import uk.gov.di.ipv.cri.passport.domain.DcsSignedEncryptedResponse;
import uk.gov.di.ipv.cri.passport.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.cri.passport.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.cri.passport.persistence.item.DcsResponseItem;
import uk.gov.di.ipv.cri.passport.service.AuthorizationCodeService;
import uk.gov.di.ipv.cri.passport.service.ConfigurationService;
import uk.gov.di.ipv.cri.passport.service.DcsCryptographyService;
import uk.gov.di.ipv.cri.passport.service.PassportService;

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
            validateRequest(queryStringParameters);
            checkQueryStringCanBeParsedToAuthenticationRequest(queryStringParameters);
            DcsPayload parsedInputForDcs = parseDscPayloadFromInput(input.getBody());
            JWSObject preparedDcsPayload = preparePayload(parsedInputForDcs);
            DcsSignedEncryptedResponse dcsResponse = doPassportCheck(preparedDcsPayload);
            DcsResponseItem unwrappedDcsResponse = unwrapDcsResponse(dcsResponse);
            passportService.persistDcsResponse(unwrappedDcsResponse);
            AuthorizationCode authorizationCode =
                    authorizationCodeService.generateAuthorizationCode();
            authorizationCodeService.persistAuthorizationCode(
                    authorizationCode.getValue(), unwrappedDcsResponse.getResourceId());

            return ApiGatewayResponseGenerator.proxyJsonResponse(HttpStatus.SC_OK, Map.of("code", authorizationCode));
        } catch (HttpResponseExceptionWithErrorBody e) {
            LOGGER.error(e.getMessage());
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    e.getStatusCode(), e.getErrorBody());
        }
    }

    private void checkQueryStringCanBeParsedToAuthenticationRequest(Map<String, List<String>> queryStringParameters) throws HttpResponseExceptionWithErrorBody {
        try {
            AuthenticationRequest.parse(queryStringParameters);
        } catch (ParseException e) {
            LOGGER.error(("Failed to parse oath query string parameters: " + e.getMessage()));
            throw new HttpResponseExceptionWithErrorBody(HttpStatus.SC_BAD_REQUEST, ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS);
        }
    }

    private DcsPayload parseDscPayloadFromInput(String input) throws HttpResponseExceptionWithErrorBody {
        try {
            return objectMapper.readValue(input, DcsPayload.class);
        } catch (JsonProcessingException e) {
            LOGGER.error(("Failed to parse payload from input: " + e.getMessage()));
            throw new HttpResponseExceptionWithErrorBody(HttpStatus.SC_BAD_REQUEST, ErrorResponse.FAILED_TO_PARSE_PASSPORT_FORM_DATA);
        }
    }

    private DcsResponseItem unwrapDcsResponse(DcsSignedEncryptedResponse response) throws HttpResponseExceptionWithErrorBody {
        try {
            return dcsCryptographyService.unwrapDcsResponse(response);
        } catch (CertificateException | java.text.ParseException | JOSEException e) {
            LOGGER.error(("Failed to unwrap response from DCS: " + e.getMessage()));
            throw new HttpResponseExceptionWithErrorBody(HttpStatus.SC_INTERNAL_SERVER_ERROR, ErrorResponse.FAILED_TO_UNWRAP_DCS_RESPONSE);
        }
    }

    private JWSObject preparePayload(DcsPayload dcsPayload) throws HttpResponseExceptionWithErrorBody {
        try {
            return dcsCryptographyService.preparePayload(dcsPayload);
        } catch (CertificateException | NoSuchAlgorithmException | InvalidKeySpecException | JOSEException | JsonProcessingException e) {
            LOGGER.error(("Failed to prepare payload for DCS: " + e.getMessage()));
            throw new HttpResponseExceptionWithErrorBody(HttpStatus.SC_INTERNAL_SERVER_ERROR, ErrorResponse.FAILED_TO_PREPARE_DCS_PAYLOAD);
        }
    }

    private DcsSignedEncryptedResponse doPassportCheck(JWSObject preparedPayload) throws HttpResponseExceptionWithErrorBody {
        try {
            return passportService.dcsPassportCheck(preparedPayload);
        } catch (IOException e) {
            LOGGER.error(("Failed to contact DCS: " + e.getMessage()));
            throw new HttpResponseExceptionWithErrorBody(HttpStatus.SC_INTERNAL_SERVER_ERROR, ErrorResponse.ERROR_CONTACTING_DCS);
        }
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

    private void validateRequest(
            Map<String, List<String>> queryStringParameters) throws HttpResponseExceptionWithErrorBody {
        if (Objects.isNull(queryStringParameters) || queryStringParameters.isEmpty()) {
            throw new HttpResponseExceptionWithErrorBody(HttpStatus.SC_BAD_REQUEST, ErrorResponse.MISSING_QUERY_PARAMETERS);
        }
    }
}
