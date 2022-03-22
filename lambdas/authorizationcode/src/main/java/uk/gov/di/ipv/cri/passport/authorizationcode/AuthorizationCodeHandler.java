package uk.gov.di.ipv.cri.passport.authorizationcode;

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
import uk.gov.di.ipv.cri.passport.authorizationcode.validation.AuthRequestValidator;
import uk.gov.di.ipv.cri.passport.library.domain.DcsResponse;
import uk.gov.di.ipv.cri.passport.library.domain.DcsSignedEncryptedResponse;
import uk.gov.di.ipv.cri.passport.library.domain.Gpg45Evidence;
import uk.gov.di.ipv.cri.passport.library.domain.PassportAttributes;
import uk.gov.di.ipv.cri.passport.library.domain.PassportGpg45Score;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.library.exceptions.EmptyDcsResponseException;
import uk.gov.di.ipv.cri.passport.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.cri.passport.library.exceptions.IpvCryptoException;
import uk.gov.di.ipv.cri.passport.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.cri.passport.library.persistence.item.PassportCheckDao;
import uk.gov.di.ipv.cri.passport.library.service.AuthorizationCodeService;
import uk.gov.di.ipv.cri.passport.library.service.ConfigurationService;
import uk.gov.di.ipv.cri.passport.library.service.DcsCryptographyService;
import uk.gov.di.ipv.cri.passport.library.service.PassportService;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

public class AuthorizationCodeHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthorizationCodeHandler.class);
    private static final ObjectMapper objectMapper =
            new ObjectMapper().registerModule(new JavaTimeModule());
    private static final int MAX_PASSPORT_GPG45_STRENGTH_VALUE = 4;
    private static final int MAX_PASSPORT_GPG45_VALIDITY_VALUE = 2;
    private static final int MIN_PASSPORT_GPG45_VALUE = 0;

    public static final String AUTHORIZATION_CODE = "code";

    private final PassportService passportService;
    private final AuthorizationCodeService authorizationCodeService;
    private final ConfigurationService configurationService;
    private final DcsCryptographyService dcsCryptographyService;
    private final AuthRequestValidator authRequestValidator;

    public AuthorizationCodeHandler(
            PassportService passportService,
            AuthorizationCodeService authorizationCodeService,
            ConfigurationService configurationService,
            DcsCryptographyService dcsCryptographyService,
            AuthRequestValidator authRequestValidator) {
        this.passportService = passportService;
        this.authorizationCodeService = authorizationCodeService;
        this.configurationService = configurationService;
        this.dcsCryptographyService = dcsCryptographyService;
        this.authRequestValidator = authRequestValidator;
    }

    public AuthorizationCodeHandler()
            throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException,
                    KeyStoreException, IOException {
        this.configurationService = new ConfigurationService();
        this.passportService = new PassportService(configurationService);
        this.authorizationCodeService = new AuthorizationCodeService(configurationService);
        this.dcsCryptographyService = new DcsCryptographyService(configurationService);
        this.authRequestValidator = new AuthRequestValidator(configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        Map<String, List<String>> queryStringParameters = getQueryStringParametersAsMap(input);

        try {
            var validationResult = authRequestValidator.validateRequest(queryStringParameters);
            if (validationResult.isPresent()) {
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        HttpStatus.SC_BAD_REQUEST, validationResult.get());
            }

            AuthenticationRequest authenticationRequest =
                    AuthenticationRequest.parse(queryStringParameters);

            PassportAttributes passportAttributes = parsePassportFormRequest(input.getBody());
            JWSObject preparedDcsPayload = preparePayload(passportAttributes);
            DcsSignedEncryptedResponse dcsResponse = doPassportCheck(preparedDcsPayload);
            DcsResponse unwrappedDcsResponse = unwrapDcsResponse(dcsResponse);
            passportAttributes.setDcsResponse(unwrappedDcsResponse);

            validateDcsResponse(unwrappedDcsResponse);

            PassportCheckDao passportCheckDao =
                    new PassportCheckDao(
                            UUID.randomUUID().toString(),
                            passportAttributes,
                            generateGpg45Score(unwrappedDcsResponse));
            passportService.persistDcsResponse(passportCheckDao);
            AuthorizationCode authorizationCode =
                    authorizationCodeService.generateAuthorizationCode();
            authorizationCodeService.persistAuthorizationCode(
                    authorizationCode.getValue(),
                    passportCheckDao.getResourceId(),
                    authenticationRequest.getRedirectionURI().toString());

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_OK, Map.of(AUTHORIZATION_CODE, authorizationCode));
        } catch (HttpResponseExceptionWithErrorBody e) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    e.getStatusCode(), e.getErrorBody());
        } catch (ParseException e) {
            LOGGER.error("Authentication request could not be parsed", e);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_BAD_REQUEST,
                    ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS);
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

    private void validateDcsResponse(DcsResponse dcsResponse)
            throws HttpResponseExceptionWithErrorBody {
        if (dcsResponse.isError()) {
            String errorMessage = dcsResponse.getErrorMessage().toString();
            LOGGER.error("DCS encounterd error: {}", errorMessage);
            throw new HttpResponseExceptionWithErrorBody(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR, ErrorResponse.DCS_RETURNED_AN_ERROR);
        }
    }

    private PassportGpg45Score generateGpg45Score(DcsResponse dcsResponse) {
        int validity =
                dcsResponse.isValid()
                        ? MAX_PASSPORT_GPG45_VALIDITY_VALUE
                        : MIN_PASSPORT_GPG45_VALUE;
        Gpg45Evidence gpg45Evidence =
                new Gpg45Evidence(MAX_PASSPORT_GPG45_STRENGTH_VALUE, validity);

        return new PassportGpg45Score(gpg45Evidence);
    }

    private PassportAttributes parsePassportFormRequest(String input)
            throws HttpResponseExceptionWithErrorBody {
        LOGGER.info("Parsing passport form data into payload for DCS");
        try {
            return objectMapper.readValue(input, PassportAttributes.class);
        } catch (JsonProcessingException e) {
            LOGGER.error(("Failed to parse payload from input: " + e.getMessage()));
            throw new HttpResponseExceptionWithErrorBody(
                    HttpStatus.SC_BAD_REQUEST, ErrorResponse.FAILED_TO_PARSE_PASSPORT_FORM_DATA);
        }
    }

    private JWSObject preparePayload(PassportAttributes passportAttributes)
            throws HttpResponseExceptionWithErrorBody {
        LOGGER.info("Preparing payload for DCS");
        try {
            return dcsCryptographyService.preparePayload(passportAttributes);
        } catch (CertificateException
                | NoSuchAlgorithmException
                | InvalidKeySpecException
                | JOSEException
                | JsonProcessingException e) {
            LOGGER.error(("Failed to prepare payload for DCS: " + e.getMessage()));
            throw new HttpResponseExceptionWithErrorBody(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_PREPARE_DCS_PAYLOAD);
        }
    }

    private DcsSignedEncryptedResponse doPassportCheck(JWSObject preparedPayload)
            throws HttpResponseExceptionWithErrorBody {
        LOGGER.info("Sending passport check to DCS");
        try {
            return passportService.dcsPassportCheck(preparedPayload);
        } catch (IOException | EmptyDcsResponseException e) {
            LOGGER.error(("Passport check with DCS failed: " + e.getMessage()));
            throw new HttpResponseExceptionWithErrorBody(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR, ErrorResponse.ERROR_CONTACTING_DCS);
        }
    }

    private DcsResponse unwrapDcsResponse(DcsSignedEncryptedResponse response)
            throws HttpResponseExceptionWithErrorBody {
        LOGGER.info("Unwrapping DCS response");
        try {
            return dcsCryptographyService.unwrapDcsResponse(response);
        } catch (CertificateException
                | java.text.ParseException
                | JOSEException
                | JsonProcessingException
                | IpvCryptoException e) {
            LOGGER.error(("Failed to unwrap response from DCS: " + e.getMessage()));
            throw new HttpResponseExceptionWithErrorBody(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_UNWRAP_DCS_RESPONSE);
        }
    }
}
