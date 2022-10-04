package uk.gov.di.ipv.cri.passport.checkpassport;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.apache.http.HttpStatus;
import org.apache.http.client.utils.URIBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import uk.gov.di.ipv.cri.common.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.cri.common.library.domain.AuditEventContext;
import uk.gov.di.ipv.cri.common.library.domain.AuditEventType;
import uk.gov.di.ipv.cri.common.library.domain.personidentity.BirthDate;
import uk.gov.di.ipv.cri.common.library.domain.personidentity.Name;
import uk.gov.di.ipv.cri.common.library.domain.personidentity.NamePart;
import uk.gov.di.ipv.cri.common.library.domain.personidentity.PersonIdentityDetailed;
import uk.gov.di.ipv.cri.common.library.exception.SqsException;
import uk.gov.di.ipv.cri.common.library.persistence.item.SessionItem;
import uk.gov.di.ipv.cri.common.library.service.AuditService;
import uk.gov.di.ipv.cri.common.library.service.SessionService;
import uk.gov.di.ipv.cri.common.library.util.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.ClientDetails;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.ClientResponse;
import uk.gov.di.ipv.cri.passport.library.config.PassportConfigurationService;
import uk.gov.di.ipv.cri.passport.library.domain.DcsPayload;
import uk.gov.di.ipv.cri.passport.library.domain.DcsResponse;
import uk.gov.di.ipv.cri.passport.library.domain.DcsSignedEncryptedResponse;
import uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.ContraIndicators;
import uk.gov.di.ipv.cri.passport.library.domain.verifiablecredential.Evidence;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.library.exceptions.EmptyDcsResponseException;
import uk.gov.di.ipv.cri.passport.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.cri.passport.library.exceptions.IpvCryptoException;
import uk.gov.di.ipv.cri.passport.library.exceptions.OAuthHttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.cri.passport.library.helpers.LogHelper;
import uk.gov.di.ipv.cri.passport.library.helpers.RequestHelper;
import uk.gov.di.ipv.cri.passport.library.persistence.item.PassportCheckDao;
import uk.gov.di.ipv.cri.passport.library.service.DcsCryptographyService;
import uk.gov.di.ipv.cri.passport.library.service.PassportService;
import uk.gov.di.ipv.cri.passport.library.service.ServiceFactory;

import java.io.IOException;
import java.net.URISyntaxException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

import static uk.gov.di.ipv.cri.passport.library.config.ConfigurationVariable.MAXIMUM_ATTEMPT_COUNT;

public class CheckPassportHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final ObjectMapper objectMapper =
            new ObjectMapper().registerModule(new JavaTimeModule());
    private static final int MAX_PASSPORT_GPG45_STRENGTH_VALUE = 4;
    private static final int MAX_PASSPORT_GPG45_VALIDITY_VALUE = 2;
    private static final int MIN_PASSPORT_GPG45_VALUE = 0;
    public static final String STATE_PARAM = "state";
    public static final String AUTH_CODE_PARAM = "code";

    public static final String RESULT = "result";
    public static final String RESULT_RETRY = "retry";

    private final PassportService passportService;
    private final PassportConfigurationService passportConfigurationService;
    private final DcsCryptographyService dcsCryptographyService;
    private final AuditService auditService;
    private final SessionService sessionService;

    public CheckPassportHandler(
            PassportService passportService,
            PassportConfigurationService passportConfigurationService,
            DcsCryptographyService dcsCryptographyService,
            AuditService auditService,
            SessionService sessionService) {
        this.passportService = passportService;
        this.passportConfigurationService = passportConfigurationService;
        this.dcsCryptographyService = dcsCryptographyService;
        this.auditService = auditService;
        this.sessionService = sessionService;
    }

    @ExcludeFromGeneratedCoverageReport
    public CheckPassportHandler()
            throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException,
                    KeyStoreException, IOException, InvalidKeyException {

        ServiceFactory serviceFactory = new ServiceFactory(objectMapper);

        this.passportConfigurationService = serviceFactory.getPassportConfigurationService();
        this.passportService = serviceFactory.getPassportService();
        this.auditService = serviceFactory.getAuditService();
        this.dcsCryptographyService = serviceFactory.getDcsCryptographyService();
        this.sessionService = serviceFactory.getSessionService();
    }

    @Override
    @Logging(clearState = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        LogHelper.attachComponentIdToLogs();
        try {
            LOGGER.info(
                    "Initiating lambda {} version {}",
                    context.getFunctionName(),
                    context.getFunctionVersion());
            final String sessionId = RequestHelper.getSessionId(input);

            LOGGER.info("Extracting session from header ID {}", sessionId);
            var sessionItem = sessionService.validateSessionId(sessionId);

            if (sessionItem == null) {
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        HttpStatus.SC_BAD_REQUEST,
                        new ErrorObject(
                                        OAuth2Error.SERVER_ERROR_CODE,
                                        ErrorResponse.PASSPORT_SESSION_NOT_FOUND.getMessage())
                                .toJSONObject());
            }

            LogHelper.attachGovukSigninJourneyIdToLogs(sessionItem.getClientSessionId());

            sessionService.incrementAttemptCount(sessionItem);

            LogHelper.attachClientIdToLogs(sessionItem.getClientId());

            DcsPayload dcsPayload = parsePassportFormRequest(input.getBody());
            JWSObject preparedDcsPayload = preparePayload(dcsPayload);

            auditService.sendAuditEvent(
                    AuditEventType.REQUEST_SENT,
                    new AuditEventContext(
                            personIdentityDetailedFromDCSPayload(dcsPayload),
                            input.getHeaders(),
                            sessionItem));

            DcsSignedEncryptedResponse dcsResponse = doPassportCheck(preparedDcsPayload);

            auditService.sendAuditEvent(
                    AuditEventType.THIRD_PARTY_REQUEST_ENDED,
                    new AuditEventContext(input.getHeaders(), sessionItem),
                    null);

            DcsResponse unwrappedDcsResponse = unwrapDcsResponse(dcsResponse);

            validateDcsResponse(unwrappedDcsResponse);

            PassportCheckDao passportCheckDao =
                    new PassportCheckDao(
                            UUID.randomUUID().toString(),
                            dcsPayload,
                            generateGpg45Score(unwrappedDcsResponse),
                            sessionItem.getUserId(),
                            sessionItem.getClientId());

            passportService.persistDcsResponse(passportCheckDao);

            // TODO DCS Response RID saving (temp location)
            sessionItem.setResponseResourceId(passportCheckDao.getResourceId());
            sessionService.updateSession(sessionItem);

            return validateResponseAndAttemptCount(sessionItem, unwrappedDcsResponse);
        } catch (OAuthHttpResponseExceptionWithErrorBody e) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    e.getStatusCode(),
                    new ErrorObject(OAuth2Error.SERVER_ERROR_CODE, e.getErrorReason())
                            .toJSONObject());
        } catch (HttpResponseExceptionWithErrorBody e) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    e.getStatusCode(), e.getErrorResponse());
        } catch (SqsException e) {
            LOGGER.error("Failed to send audit event to SQS queue because: {}", e.getMessage());
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_BAD_REQUEST,
                    new ErrorObject(
                                    OAuth2Error.SERVER_ERROR_CODE,
                                    ErrorResponse.FAILED_TO_SEND_AUDIT_MESSAGE_TO_SQS_QUEUE
                                            .getMessage())
                            .toJSONObject());
        } catch (URISyntaxException e) {
            LOGGER.error("Failed to construct redirect uri because: {}", e.getMessage());
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    private ClientResponse generateClientSuccessResponse(SessionItem sessionItem)
            throws URISyntaxException {
        URIBuilder redirectUri =
                new URIBuilder(sessionItem.getRedirectUri())
                        .addParameter(AUTH_CODE_PARAM, sessionItem.getAuthorizationCode());

        if (StringUtils.isNotBlank(sessionItem.getState())) {
            redirectUri.addParameter(STATE_PARAM, sessionItem.getState());
        }

        return new ClientResponse(new ClientDetails(redirectUri.build().toString()));
    }

    private APIGatewayProxyResponseEvent validateResponseAndAttemptCount(
            SessionItem sessionItem, DcsResponse unwrappedDcsResponse) throws URISyntaxException {

        int attemptCount = sessionItem.getAttemptCount();

        if (unwrappedDcsResponse.isValid()
                || attemptCount
                        >= Integer.parseInt(
                                passportConfigurationService.getStackSsmParameter(
                                        MAXIMUM_ATTEMPT_COUNT))) {
            LOGGER.info("Passport sequence finished with {} attempts", attemptCount);

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_OK, generateClientSuccessResponse(sessionItem));
        }

        LOGGER.info("DCS response is not valid requesting retry");

        return ApiGatewayResponseGenerator.proxyJsonResponse(
                HttpStatus.SC_OK, Map.of(RESULT, RESULT_RETRY));
    }

    private void validateDcsResponse(DcsResponse dcsResponse)
            throws OAuthHttpResponseExceptionWithErrorBody {
        if (dcsResponse.isError()) {
            String errorMessage = dcsResponse.getErrorMessage().toString();
            LOGGER.error("DCS encountered an error: {}", errorMessage);
            throw new OAuthHttpResponseExceptionWithErrorBody(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR, ErrorResponse.DCS_RETURNED_AN_ERROR);
        }
    }

    private Evidence generateGpg45Score(DcsResponse dcsResponse) {
        return new Evidence(
                UUID.randomUUID().toString(),
                MAX_PASSPORT_GPG45_STRENGTH_VALUE,
                calculateValidity(dcsResponse),
                calculateContraIndicators(dcsResponse));
    }

    private DcsPayload parsePassportFormRequest(String input)
            throws OAuthHttpResponseExceptionWithErrorBody {
        LOGGER.info("Parsing passport form data into payload for DCS");
        try {
            return objectMapper.readValue(input, DcsPayload.class);
        } catch (JsonProcessingException e) {
            LOGGER.error(("Failed to parse payload from input: " + e.getMessage()));
            throw new OAuthHttpResponseExceptionWithErrorBody(
                    HttpStatus.SC_BAD_REQUEST, ErrorResponse.FAILED_TO_PARSE_PASSPORT_FORM_DATA);
        }
    }

    private JWSObject preparePayload(DcsPayload dcsPayload)
            throws OAuthHttpResponseExceptionWithErrorBody {
        LOGGER.info("Preparing payload for DCS");
        try {
            return dcsCryptographyService.preparePayload(dcsPayload);
        } catch (CertificateException
                | NoSuchAlgorithmException
                | InvalidKeySpecException
                | JOSEException
                | JsonProcessingException e) {
            LOGGER.error(("Failed to prepare payload for DCS: " + e.getMessage()));
            throw new OAuthHttpResponseExceptionWithErrorBody(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_PREPARE_DCS_PAYLOAD);
        }
    }

    private DcsSignedEncryptedResponse doPassportCheck(JWSObject preparedPayload)
            throws OAuthHttpResponseExceptionWithErrorBody {
        LOGGER.info("Sending passport check to DCS");
        try {
            return passportService.dcsPassportCheck(preparedPayload);
        } catch (IOException | EmptyDcsResponseException e) {
            LOGGER.error(("Passport check with DCS failed: " + e.getMessage()));
            throw new OAuthHttpResponseExceptionWithErrorBody(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR, ErrorResponse.ERROR_CONTACTING_DCS);
        }
    }

    private DcsResponse unwrapDcsResponse(DcsSignedEncryptedResponse response)
            throws OAuthHttpResponseExceptionWithErrorBody {
        LOGGER.info("Unwrapping DCS response");
        try {
            return dcsCryptographyService.unwrapDcsResponse(response);
        } catch (CertificateException
                | java.text.ParseException
                | JOSEException
                | IpvCryptoException e) {
            LOGGER.error(("Failed to unwrap response from DCS: " + e.getMessage()));
            throw new OAuthHttpResponseExceptionWithErrorBody(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_UNWRAP_DCS_RESPONSE);
        }
    }

    private int calculateValidity(DcsResponse dcsResponse) {
        return dcsResponse.isValid() ? MAX_PASSPORT_GPG45_VALIDITY_VALUE : MIN_PASSPORT_GPG45_VALUE;
    }

    private List<ContraIndicators> calculateContraIndicators(DcsResponse dcsResponse) {
        return dcsResponse.isValid() ? null : List.of(ContraIndicators.D02);
    }

    private PersonIdentityDetailed personIdentityDetailedFromDCSPayload(DcsPayload dcsPayload) {

        List<NamePart> nameParts = new ArrayList<>();

        // The front has combined firstnames and middle names in one list
        for (String foreName : dcsPayload.getForenames()) {
            if (Objects.nonNull(foreName)) {
                nameParts.add(getNamePart(foreName, "GivenName"));
            }
        }

        if (Objects.nonNull(dcsPayload.getSurname())) {
            nameParts.add(getNamePart(dcsPayload.getSurname(), "FamilyName"));
        }

        Name personsName = new Name();
        personsName.setNameParts(nameParts);

        BirthDate birthDate = new BirthDate();
        birthDate.setValue(dcsPayload.getDateOfBirth());

        return new PersonIdentityDetailed(List.of(personsName), List.of(birthDate), null);
    }

    private NamePart getNamePart(String value, String type) {
        NamePart namePart = new NamePart();
        namePart.setValue(value);
        namePart.setType(type);
        return namePart;
    }
}
