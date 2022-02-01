package uk.gov.di.ipv.cri.passport.jwtverification;

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
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.passport.library.error.ErrorResponse;
import uk.gov.di.ipv.cri.passport.library.service.ConfigurationService;

import java.io.ByteArrayInputStream;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;
@ExtendWith(MockitoExtension.class)
class JwtVerificationHandlerTest {

    @Mock
    private ConfigurationService configurationService;

    private  JwtVerificationHandler underTest ;

    private SignedJWT signedJWT;

    @Mock
    Context context;

    private static final String BASE64_CERT =
            "MIIDZzCCAk+gAwIBAgIBATANBgkqhkiG9w0BAQsFADB3MQswCQYDVQQGEwJVSzEXMBUGA1UECBMOR3JlYXRlciBMb25kb24xDzANBgNVBAcTBkxvbmRvbjEXMBUGA1UEChMOQ2FiaW5ldCBPZmZpY2UxDDAKBgNVBAsTA0dEUzEXMBUGA1UEAxMOTXkgY29tbW9uIG5hbWUwHhcNMjIwMTMxMTExNDM3WhcNMjMwMTMxMTExNDM3WjB3MQswCQYDVQQGEwJVSzEXMBUGA1UECBMOR3JlYXRlciBMb25kb24xDzANBgNVBAcTBkxvbmRvbjEXMBUGA1UEChMOQ2FiaW5ldCBPZmZpY2UxDDAKBgNVBAsTA0dEUzEXMBUGA1UEAxMOTXkgY29tbW9uIG5hbWUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDCRZHUZZOG6W9hrxx/qo8hl9c6rd/0HCed7Vd2DidJ2yRTjbMZ0q8S9OdxTO2H0Wrrt1r4k6RqRKDImdcRqsJKM8iamcS8kYnQHUdHaqnwcFkDtM29A/57V0by2H/fUJss5MqLCE6hBKnrNc/WrI5VCx2LNEe833yDM1fYDjh0CKJK8e0bXMRCTn1sl2wmmBucRaXIZa2msey6SpgxG7REuVsc+Y804yuZAOaTyFP485D8QMVjwl/KRGVich7XYaxTZI3N4KGpS0K9Ui0U+FwuCxsDDdABQ1B2acINZ1ookghLp3EsnpvUJlHw+rPvvqOd18D64TQIDm67O4jK+c4zAgMBAAEwDQYJKoZIhvcNAQELBQADggEBADVrL7p+L5Y38LSMkIJF+fNTXN2xb0cFwn6fHLiD1Jpvq2LoMU18P1lBT4ZFsPFM8OPk58m6Nid8GVJpp+Pz/8a7Uhx3PfpB2uKzmpwBktBu5xpdE+DS/omxnlY91vAnCJaA3NdBYaDGavbs3J0rCR5DpH56hXikmtR3IzGYgrX3TJJghl6vWXZsW/J9nG5+W62SOX9hQUzj3rkXYKfcugODRAsBSC72zOgOU8+7MyDJkX9ndS6UOA5owUDonv75rVEDHNV/vcKrIrs43gmmcQ+PnxU7RwbCsUAN/si4emkR8zAdCQVvi0VFh9woikHOZvlXwm/GGINiLDi8E3kxL10=";

    //private static final String BASE64_CERT1=
     //       "eyJhbGciOiJIUzI1NiJ9.eyJkYXRlT2ZCaXJ0aHMiOlsiMDFcLzAxXC8xOTgwIiwiMDJcLzAxXC8xOTgwIl0sImFkZHJlc3NlcyI6WyIxMjMgcmFuZG9tIHN0cmVldCwgTTEzIDdHRSJdLCJnaXZlbk5hbWVzIjpbIkRhbmllbCIsIkRhbiIsIkRhbm55Il19.9DhsBeDOad7UEqGcNH1lQn0MuPGJ9m4NcWJAL4HMSoM,";
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

        underTest = new JwtVerificationHandler(configurationService);
    }

    @Test
    void shouldReturn200WhenGivenValidJWT() throws CertificateException {
        when(configurationService.getClientCert("TEST")).thenReturn(getCertificate(BASE64_CERT));

        var event = new APIGatewayProxyRequestEvent();
        Map<String, String> map = new HashMap<>();
        map.put("client_id", "TEST");
        event.setHeaders(map);
        event.setBody(signedJWT.serialize());

        var response = underTest.handleRequest(event, context);
        assertEquals(200, response.getStatusCode());
    }

    @Test
    void shouldReturnClaimsAsJsonFromJWT() throws JsonProcessingException, CertificateException {
        when(configurationService.getClientCert("TEST")).thenReturn(getCertificate(BASE64_CERT));
        var event = new APIGatewayProxyRequestEvent();
        Map<String, String> map = new HashMap<>();
        map.put("client_id", "TEST");
        event.setHeaders(map);
        event.setBody(signedJWT.serialize());

        var response = underTest.handleRequest(event, context);

        ObjectMapper objectMapper = new ObjectMapper();
        Map<String, Object> claims = objectMapper.readValue(response.getBody(), new TypeReference<>() {});
        assertEquals(Arrays.asList("01/01/1980", "02/01/1980"), claims.get("dateOfBirths"));
        assertEquals(Collections.singletonList("123 random street, M13 7GE"), claims.get("addresses"));
        assertEquals(Arrays.asList("Daniel", "Dan", "Danny"), claims.get("givenNames"));
    }

    @Test
    void shouldReturn400IfMissingJWT() throws JsonProcessingException, CertificateException {
        var event = new APIGatewayProxyRequestEvent();
        Map<String, String> map = new HashMap<>();
        map.put("client_id", "TEST");
        event.setHeaders(map);
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
        Map<String, String> map = new HashMap<>();
        map.put("client_id", "TEST");
        event.setHeaders(map);
        event.setBody("Not a valid JWT");

        var response = underTest.handleRequest(event, context);

        ObjectMapper objectMapper = new ObjectMapper();
        Map<String, Object> error = objectMapper.readValue(response.getBody(), new TypeReference<>() {});
        assertEquals(400, response.getStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_PARSE_SHARED_ATTRIBUTES_JWT.getCode(), error.get("code"));
        assertEquals(ErrorResponse.FAILED_TO_PARSE_SHARED_ATTRIBUTES_JWT.getMessage(), error.get("message"));
    }

    @Test
    void shouldReturn400IfClientIdIsNotSet() throws JsonProcessingException {
        var event = new APIGatewayProxyRequestEvent();

        var response = underTest.handleRequest(event, context);

        ObjectMapper objectMapper = new ObjectMapper();
        Map<String, Object> error = objectMapper.readValue(response.getBody(), new TypeReference<>() {});
        assertEquals(400, response.getStatusCode());
        assertEquals(ErrorResponse.MISSING_CLIENT_ID_QUERY_PARAMETER.getCode(), error.get("code"));
        assertEquals(ErrorResponse.MISSING_CLIENT_ID_QUERY_PARAMETER.getMessage(), error.get("message"));
    }

    private Certificate getCertificate(String base64certificate) throws CertificateException {
        byte[] binaryCertificate = Base64.getDecoder().decode(base64certificate);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return factory.generateCertificate(new ByteArrayInputStream(binaryCertificate));
    }

}

