package uk.gov.di.ipv.cri.passport.sharedattributes;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SharedAttributesHandlerTest {

    private final SharedAttributesHandler underTest = new SharedAttributesHandler();

    private SignedJWT signedJWT;

    @Mock Context context;

    @BeforeEach
    void setUp() throws JOSEException {
        List<String> givenNames = Arrays.asList("Daniel", "Dan", "Danny");
        List<String> dateOfBirths = Arrays.asList("01/01/1980", "02/01/1980");
        List<String> addresses = Collections.singletonList("123 random street, M13 7GE");
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("givenNames", givenNames)
                .claim("dateOfBirths", dateOfBirths)
                .claim("addresses", addresses)
                .build();

        SecureRandom random = new SecureRandom();
        byte[] sharedSecret = new byte[32];
        random.nextBytes(sharedSecret);

        JWSSigner signer = new MACSigner(sharedSecret);

        signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);

        signedJWT.sign(signer);
    }

    @Test
    void shouldReturn200WhenGivenValidJWT() {
        var event = new APIGatewayProxyRequestEvent();
        event.setBody(signedJWT.serialize());

        var response = underTest.handleRequest(event, context);
        assertEquals(200, response.getStatusCode());
    }

    @Test
    void shouldReturnClaimsAsJsonFromJWT() throws JsonProcessingException {
        var event = new APIGatewayProxyRequestEvent();
        event.setBody(signedJWT.serialize());

        var response = underTest.handleRequest(event, context);

        ObjectMapper objectMapper = new ObjectMapper();
        Map<String, Object> claims = objectMapper.readValue(response.getBody(), new TypeReference<>() {});
        assertEquals(Arrays.asList("01/01/1980", "02/01/1980"), claims.get("dateOfBirths"));
        assertEquals(Collections.singletonList("123 random street, M13 7GE"), claims.get("addresses"));
        assertEquals(Arrays.asList("Daniel", "Dan", "Danny"), claims.get("givenNames"));
    }

    @Test
    void shouldReturn400IfMissingJWT() throws JsonProcessingException {
        var event = new APIGatewayProxyRequestEvent();
        event.setBody(null);

        var response = underTest.handleRequest(event, context);

        ObjectMapper objectMapper = new ObjectMapper();
        Map<String, Object> error = objectMapper.readValue(response.getBody(), new TypeReference<>() {});
        assertEquals(400, response.getStatusCode());
        assertEquals(ErrorResponse.MISSING_SHARED_ATTRIBUTES_JWT.getCode(), error.get("code"));
        assertEquals(ErrorResponse.MISSING_SHARED_ATTRIBUTES_JWT.getMessage(), error.get("message"));
    }

    @Test
    void shouldReturn400IfFailedToParseJWT() throws JsonProcessingException {
        var event = new APIGatewayProxyRequestEvent();
        event.setBody("Not a valid JWT");

        var response = underTest.handleRequest(event, context);

        ObjectMapper objectMapper = new ObjectMapper();
        Map<String, Object> error = objectMapper.readValue(response.getBody(), new TypeReference<>() {});
        assertEquals(400, response.getStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_PARSE_SHARED_ATTRIBUTES_JWT.getCode(), error.get("code"));
        assertEquals(ErrorResponse.FAILED_TO_PARSE_SHARED_ATTRIBUTES_JWT.getMessage(), error.get("message"));
    }
}
