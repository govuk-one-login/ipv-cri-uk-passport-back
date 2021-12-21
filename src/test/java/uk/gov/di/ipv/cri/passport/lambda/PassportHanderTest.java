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
import uk.gov.di.ipv.cri.passport.service.PassportService;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(MockitoExtension.class)
public class PassportHanderTest {
    @Mock private Context context;
    @Mock private PassportService passPortService;

    @Test
    void shouldReturn200() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        var oauthParams = Map.of(
                "redirect_uri", "http://example.com",
                "client_id", "12345",
                "response_type", "code",
                "scope", "openid"
        );
        event.setQueryStringParameters(oauthParams);

        var passportFormData = Map.of(
                "passportNumber", "1234567890",
                "surname", "Tattsyrup",
                "forenames", "Tubbs",
                "dateOfBirth", "1984-09-28T10:15:30.00Z",
                "expiryDate", "2024-09-03T10:15:30.00Z"
        );
        var objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule());
        String s = objectMapper.writeValueAsString(passportFormData);

        event.setBody(s);


        PassportHandler passportHandler = new PassportHandler(passPortService);
        var response = passportHandler.handleRequest(event, context);

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());

    }
}
