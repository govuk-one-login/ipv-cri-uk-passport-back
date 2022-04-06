package uk.gov.di.ipv.cri.passport.sharedattributes;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.library.service.ConfigurationService;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.cri.passport.library.helpers.fixtures.TestFixtures.EC_PRIVATE_KEY_1;
import static uk.gov.di.ipv.cri.passport.library.helpers.fixtures.TestFixtures.EC_PUBLIC_JWK_1;
import static uk.gov.di.ipv.cri.passport.sharedattributes.SharedAttributesHandler.CLAIMS_CLAIM;
import static uk.gov.di.ipv.cri.passport.sharedattributes.SharedAttributesHandler.VC_HTTP_API_CLAIM;

@ExtendWith(MockitoExtension.class)
class SharedAttributesHandlerTest {

    public static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Mock private ConfigurationService configurationService;

    private SharedAttributesHandler underTest;

    private SignedJWT signedJWT;

    @Mock Context context;

    @BeforeEach
    void setUp() throws JOSEException, InvalidKeySpecException, NoSuchAlgorithmException {
        Map<String, List<String>> vcHttpApiClaim =
                Map.of(
                        "givenNames", Arrays.asList("Daniel", "Dan", "Danny"),
                        "dateOfBirths", Arrays.asList("01/01/1980", "02/01/1980"),
                        "addresses", Collections.singletonList("123 random street, M13 7GE"));

        JWTClaimsSet claimsSet =
                new JWTClaimsSet.Builder()
                        .claim(CLAIMS_CLAIM, Map.of(VC_HTTP_API_CLAIM, vcHttpApiClaim))
                        .build();

        signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.ES256), claimsSet);
        signedJWT.sign(new ECDSASigner(getPrivateKey()));

        underTest = new SharedAttributesHandler(configurationService);
    }

    @Test
    void shouldReturn200WhenGivenValidJWT() throws Exception {
        when(configurationService.getClientSigningPublicJwk("TEST"))
                .thenReturn(ECKey.parse(EC_PUBLIC_JWK_1));

        var event = new APIGatewayProxyRequestEvent();
        Map<String, String> map = new HashMap<>();
        map.put("client_id", "TEST");
        event.setHeaders(map);
        event.setBody(signedJWT.serialize());

        var response = underTest.handleRequest(event, context);
        assertEquals(200, response.getStatusCode());
    }

    @Test
    void shouldReturnClaimsAsJsonFromJWT() throws Exception {
        when(configurationService.getClientSigningPublicJwk("TEST"))
                .thenReturn(ECKey.parse(EC_PUBLIC_JWK_1));
        var event = new APIGatewayProxyRequestEvent();
        Map<String, String> map = new HashMap<>();
        map.put("client_id", "TEST");
        event.setHeaders(map);
        event.setBody(signedJWT.serialize());

        var response = underTest.handleRequest(event, context);

        Map<String, Object> claims =
                OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});
        assertEquals(Arrays.asList("01/01/1980", "02/01/1980"), claims.get("dateOfBirths"));
        assertEquals(
                Collections.singletonList("123 random street, M13 7GE"), claims.get("addresses"));
        assertEquals(Arrays.asList("Daniel", "Dan", "Danny"), claims.get("givenNames"));
    }

    @Test
    void shouldReturn400IfMissingJWT() throws JsonProcessingException {
        var event = new APIGatewayProxyRequestEvent();
        Map<String, String> map = new HashMap<>();
        map.put("client_id", "TEST");
        event.setHeaders(map);
        event.setBody(null);

        var response = underTest.handleRequest(event, context);

        Map<String, Object> error =
                OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});
        assertEquals(400, response.getStatusCode());
        assertEquals(ErrorResponse.MISSING_SHARED_ATTRIBUTES_JWT.getCode(), error.get("code"));
        assertEquals(
                ErrorResponse.MISSING_SHARED_ATTRIBUTES_JWT.getMessage(), error.get("message"));
    }

    @Test
    void shouldReturn400IfFailedToParseJWT() throws JsonProcessingException {
        var event = new APIGatewayProxyRequestEvent();
        Map<String, String> map = new HashMap<>();
        map.put("client_id", "TEST");
        event.setHeaders(map);
        event.setBody("Not a valid JWT");

        var response = underTest.handleRequest(event, context);

        Map<String, Object> error =
                OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});
        assertEquals(400, response.getStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_PARSE.getCode(), error.get("code"));
        assertEquals(ErrorResponse.FAILED_TO_PARSE.getMessage(), error.get("message"));
    }

    @Test
    void shouldReturn400IfClientIdIsNotSet() throws JsonProcessingException {
        var event = new APIGatewayProxyRequestEvent();

        var response = underTest.handleRequest(event, context);

        Map<String, Object> error =
                OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});
        assertEquals(400, response.getStatusCode());
        assertEquals(ErrorResponse.MISSING_CLIENT_ID_QUERY_PARAMETER.getCode(), error.get("code"));
        assertEquals(
                ErrorResponse.MISSING_CLIENT_ID_QUERY_PARAMETER.getMessage(), error.get("message"));
    }

    @Test
    void shouldReturn400WhenSignatureVerificationFails() throws Exception {
        when(configurationService.getClientSigningPublicJwk("TEST"))
                .thenReturn(ECKey.parse(EC_PUBLIC_JWK_1));

        var event = new APIGatewayProxyRequestEvent();
        Map<String, String> map = new HashMap<>();
        map.put("client_id", "TEST");
        event.setHeaders(map);
        String badSignatureSignedJwt = signedJWT.serialize();
        event.setBody(
                badSignatureSignedJwt.substring(0, badSignatureSignedJwt.length() - 4) + "nope");

        var response = underTest.handleRequest(event, context);

        Map<String, Object> error =
                OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});
        assertEquals(400, response.getStatusCode());
        assertEquals(ErrorResponse.JWT_SIGNATURE_IS_INVALID.getCode(), error.get("code"));
        assertEquals(ErrorResponse.JWT_SIGNATURE_IS_INVALID.getMessage(), error.get("message"));
    }

    @Test
    void shouldReturn400WhenJwkParsingFails() throws Exception {
        when(configurationService.getClientSigningPublicJwk("TEST"))
                .thenThrow(new ParseException("Failed to parse JWK", 0));

        var event = new APIGatewayProxyRequestEvent();
        Map<String, String> map = new HashMap<>();
        map.put("client_id", "TEST");
        event.setHeaders(map);
        event.setBody(signedJWT.serialize());

        var response = underTest.handleRequest(event, context);

        Map<String, Object> error =
                OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});
        assertEquals(400, response.getStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_PARSE.getCode(), error.get("code"));
        assertEquals(ErrorResponse.FAILED_TO_PARSE.getMessage(), error.get("message"));
    }

    @Test
    void shouldReturn400WhenClaimsClaimMissing() throws Exception {
        when(configurationService.getClientSigningPublicJwk("TEST"))
                .thenReturn(ECKey.parse(EC_PUBLIC_JWK_1));

        JWTClaimsSet claimsSet =
                new JWTClaimsSet.Builder().claim("NO_CLAIMS_CLAIM_PRESENT", "Nope").build();

        SignedJWT signedJwtWithoutClaim =
                new SignedJWT(new JWSHeader(JWSAlgorithm.ES256), claimsSet);
        signedJwtWithoutClaim.sign(new ECDSASigner(getPrivateKey()));

        var event = new APIGatewayProxyRequestEvent();
        Map<String, String> map = new HashMap<>();
        map.put("client_id", "TEST");
        event.setHeaders(map);
        event.setBody(signedJwtWithoutClaim.serialize());

        var response = underTest.handleRequest(event, context);

        Map<String, Object> error =
                OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});
        assertEquals(400, response.getStatusCode());
        assertEquals(ErrorResponse.VC_HTTP_API_CLAIM_MISSING.getCode(), error.get("code"));
        assertEquals(ErrorResponse.VC_HTTP_API_CLAIM_MISSING.getMessage(), error.get("message"));
    }

    @Test
    void shouldReturn400WhenVcHttpApiClaimMissingFromClaimsClaim() throws Exception {
        when(configurationService.getClientSigningPublicJwk("TEST"))
                .thenReturn(ECKey.parse(EC_PUBLIC_JWK_1));

        JWTClaimsSet claimsSet =
                new JWTClaimsSet.Builder()
                        .claim("claims", Map.of("not_vc_http_api_claim", "nope"))
                        .build();

        SignedJWT signedJwtWithoutClaim =
                new SignedJWT(new JWSHeader(JWSAlgorithm.ES256), claimsSet);
        signedJwtWithoutClaim.sign(new ECDSASigner(getPrivateKey()));

        var event = new APIGatewayProxyRequestEvent();
        Map<String, String> map = new HashMap<>();
        map.put("client_id", "TEST");
        event.setHeaders(map);
        event.setBody(signedJwtWithoutClaim.serialize());

        var response = underTest.handleRequest(event, context);

        Map<String, Object> error =
                OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});
        assertEquals(400, response.getStatusCode());
        assertEquals(ErrorResponse.VC_HTTP_API_CLAIM_MISSING.getCode(), error.get("code"));
        assertEquals(ErrorResponse.VC_HTTP_API_CLAIM_MISSING.getMessage(), error.get("message"));
    }

    private ECPrivateKey getPrivateKey() throws InvalidKeySpecException, NoSuchAlgorithmException {
        return (ECPrivateKey)
                KeyFactory.getInstance("EC")
                        .generatePrivate(
                                new PKCS8EncodedKeySpec(
                                        Base64.getDecoder().decode(EC_PRIVATE_KEY_1)));
    }
}
