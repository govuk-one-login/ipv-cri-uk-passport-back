package uk.gov.di.ipv.cri.passport.service;

import com.google.gson.Gson;
import com.nimbusds.jose.JOSEException;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.apache.http.HttpResponse;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.UUID;

import org.apache.http.HttpStatus;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.cri.passport.domain.ErrorResponse;
import uk.gov.di.ipv.cri.passport.domain.PassportException;
import uk.gov.di.ipv.cri.passport.dto.DcsCheckRequestDto;
import uk.gov.di.ipv.cri.passport.dto.DcsPayload;
import uk.gov.di.ipv.cri.passport.dto.DcsResponse;
import uk.gov.di.ipv.cri.passport.helpers.Postpassport;

public class PassportService {

    private final SigningService signingService;
    private final Gson gson = new Gson();
    private final HttpClient httpClient;
    private final  ConfigurationService configurationService;

    private static final Logger LOGGER = LoggerFactory.getLogger(PassportService.class);

    public PassportService(SigningService signingService, HttpClient httpClient,ConfigurationService configurationService) {
        this.signingService = signingService;
        this.httpClient = httpClient;
        this.configurationService = configurationService;
    }

    public PassportService() {
        this.signingService = new SigningService();
        this.httpClient = Postpassport.generateHttpClient();
        this.configurationService = new ConfigurationService();
    }

    public DcsResponse postValidPassportRequest(DcsCheckRequestDto dto) {

        try {
            var dcsPayload = createValidPassportRequestPayload(dto);
            String signed = signingService.signData(gson.toJson(dcsPayload));
            //String encrypted = encryptionService.encrypt(signed, configurationService.getDcsEncryptionCert());
            //String secondSigned = signPayload(encrypted);

            HttpPost request = new HttpPost(configurationService.getPassportPostUri());
            request.addHeader("content-type", "application/jose");
            request.setEntity(new StringEntity(signed));
            HttpResponse response = httpClient.execute(request);


            if (!(response == null)) {
                return HandleResponse(response, dcsPayload);
            }
        } catch (IOException |UnsupportedOperationException | CertificateException | NoSuchAlgorithmException | InvalidKeySpecException | JOSEException | PassportException e) {
            // TODO - create new our custom exception
            // TODO - throw new PassportHandlerException
            LOGGER.error("Error post passport : {}", e.getMessage(), e);
            throw new PassportException(
                    HTTPResponse.SC_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_PARSE_PASSPORT_FORM_DATA);
        }
        return null;
    }

    private DcsPayload createValidPassportRequestPayload(DcsCheckRequestDto dto) {
        var correlationId = UUID.randomUUID();
        var requestId = UUID.randomUUID();
        LOGGER.info("Creating new DCS payload (requestId: {}, correlationId: {})", requestId, correlationId);

        return new DcsPayload(correlationId, requestId, Timestamp.from(Instant.now()), dto.getPassportNumber(),
                dto.getSurname(), new String[]{dto.getForenames()}, dto.getDateOfBirth(), dto.getExpiryDate());
    }

    private DcsResponse HandleResponse(HttpResponse response, DcsPayload dcsPayload) {

        DcsResponse dcsResponse;

        if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
            LOGGER.info(
                    "Received a 200 response from DCS (requestId: {}, correlationId: {})",
                    dcsPayload.getRequestId(),
                    dcsPayload.getCorrelationId()
            );

            dcsResponse = setResponse(dcsPayload, false, true, new String[]{""});

        } else if (response.getStatusLine().getStatusCode() >= 400 && response.getStatusLine().getStatusCode() < 500) {
            LOGGER.warn(
                    "Received a 4xx response from DCS (requestId: {}, correlationId: {})",
                    dcsPayload.getRequestId(),
                    dcsPayload.getCorrelationId()
            );
            dcsResponse = setResponse(dcsPayload, true, false, new String[]{"DCS responded with a 4xx error"});

        } else {
            LOGGER.error(
                    "Unable to process request (requestId: {}, correlationId: {})",
                    dcsPayload.getRequestId(),
                    dcsPayload.getCorrelationId()
            );
            dcsResponse = setResponse(dcsPayload, true, false, new String[]{"DCS responded with an exception"});
        }

        return dcsResponse;
    }

    private DcsResponse setResponse(DcsPayload dcsPayload, boolean error, boolean valid, String[] errorMessage) {
        return new DcsResponse(dcsPayload.getCorrelationId(), dcsPayload.getRequestId(), error, valid, errorMessage);
    }

}
