package uk.gov.di.ipv.cri.passport.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.passport.error.ErrorResponse;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(MockitoExtension.class)
public class PassportHandlerTest {

    private final ObjectMapper objectMapper =
            new ObjectMapper().registerModule(new JavaTimeModule());
    private final PassportHandler passportHandler = new PassportHandler();
    private final Map<String, String> validPassportFormData =
            Map.of(
                    "passportNumber", "1234567890",
                    "surname", "Tattsyrup",
                    "forenames", "[Tubbs]",
                    "dateOfBirth", "1984-09-28T10:15:30",
                    "expiryDate", "2024-09-03T10:15:30");

    @Mock private Context context;

    @Test
    void shouldReturn200WithCorrectFormData() throws JsonProcessingException {
        var event = new APIGatewayProxyRequestEvent();
        event.setBody(objectMapper.writeValueAsString(validPassportFormData));

        var response = passportHandler.handleRequest(event, context);

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldReturn400IfDataIsMissing() throws JsonProcessingException {
        var formFields = validPassportFormData.keySet();
        for (String keyToRemove : formFields) {
            var event = new APIGatewayProxyRequestEvent();
            event.setBody(
                    objectMapper.writeValueAsString(
                            new HashMap<>(validPassportFormData).remove(keyToRemove)));

            var response = passportHandler.handleRequest(event, context);
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
        mangledDateInput.put("dateOfBirth", "1984-09-28T10:15:30.00Z");

        var event = new APIGatewayProxyRequestEvent();
        event.setBody(objectMapper.writeValueAsString(mangledDateInput));

        var response = passportHandler.handleRequest(event, context);
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
