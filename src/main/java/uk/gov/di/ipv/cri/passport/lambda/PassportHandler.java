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
import uk.gov.di.ipv.cri.passport.dto.DcsCheckRequestDto;
import uk.gov.di.ipv.cri.passport.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.helpers.ApiGatewayResponseGenerator;

public class PassportHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(PassportHandler.class);
    private static final ObjectMapper objectMapper =
            new ObjectMapper().registerModule(new JavaTimeModule());

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {

        DcsCheckRequestDto dcsCheckRequestDto;
        try {
            dcsCheckRequestDto = objectMapper.readValue(input.getBody(), DcsCheckRequestDto.class);
        } catch (JsonProcessingException e) {
            LOGGER.error("Passport form data could not be parsed", e);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_BAD_REQUEST, ErrorResponse.FAILED_TO_PARSE_PASSPORT_FORM_DATA);
        }

        return ApiGatewayResponseGenerator.proxyJsonResponse(HttpStatus.SC_OK, dcsCheckRequestDto);
    }
}
