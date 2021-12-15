package uk.gov.di.ipv.cri.passport.lambda;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.GetPublicKeyRequest;
import com.amazonaws.services.kms.model.GetPublicKeyResult;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import net.minidev.json.JSONObject;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.passport.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.signing.KmsSigner;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

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

    @Test
    void signingSomethingWithKms()
            throws NoSuchAlgorithmException, InvalidKeySpecException, JOSEException,
                    ParseException {
        String keyId = "5b32227e-b835-4b4a-a15d-4c050ca01af4";
        AWSKMS kmsClient = AWSKMSClientBuilder.defaultClient();

        GetPublicKeyRequest getPublicKeyRequest = new GetPublicKeyRequest().withKeyId(keyId);
        GetPublicKeyResult publicKey = kmsClient.getPublicKey(getPublicKeyRequest);

        JSONObject jsonPayload = new JSONObject(Map.of("Will this work?", "Who can say..."));

        JWSObject jwsObject =
                new JWSObject(
                        new JWSHeader.Builder(JWSAlgorithm.RS256)
                                .keyID(publicKey.getKeyId())
                                .build(),
                        new Payload(jsonPayload));

        KmsSigner kmsSigner = new KmsSigner(keyId);

        jwsObject.sign(kmsSigner);

        String serializedSignedObject = jwsObject.serialize();
        JWSObject parsedJWSObject = JWSObject.parse(serializedSignedObject);

        RSAPublicKey rsaPublic =
                (RSAPublicKey)
                        KeyFactory.getInstance("RSA")
                                .generatePublic(
                                        new X509EncodedKeySpec(publicKey.getPublicKey().array()));
        JWSVerifier verifier = new RSASSAVerifier(rsaPublic);

        assertTrue(parsedJWSObject.verify(verifier));
    }
}
