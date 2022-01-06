package uk.gov.di.ipv.cri.passport.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.apache.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.cri.passport.domain.DcsPayload;
import uk.gov.di.ipv.cri.passport.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.cri.passport.service.PassportService;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

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

    public PassportHandler(PassportService passportService) {
        this.passportService = passportService;
    }

    public PassportHandler()
            throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException,
                    KeyStoreException, IOException {
        this.passportService = new PassportService();
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        DcsPayload dcsPayload;
        try {
            dcsPayload = objectMapper.readValue(input.getBody(), DcsPayload.class);

        } catch (JsonProcessingException e) {
            LOGGER.error("Passport form data could not be parsed", e);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_BAD_REQUEST, ErrorResponse.FAILED_TO_PARSE_PASSPORT_FORM_DATA);
        }

        try {
            String jsonPayload = objectMapper.writeValueAsString(dcsPayload);
            String response = passportService.dcsPassportCheck(jsonPayload);

            passportService.persistDcsResponse(response);

            return ApiGatewayResponseGenerator.proxyJsonResponse(HttpStatus.SC_OK, response);

        } catch (IOException e) {
            e.printStackTrace();
        }

        return ApiGatewayResponseGenerator.proxyJsonResponse(HttpStatus.SC_OK, dcsPayload);
    }
}
