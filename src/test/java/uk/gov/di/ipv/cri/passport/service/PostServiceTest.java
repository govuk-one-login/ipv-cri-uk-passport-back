package uk.gov.di.ipv.cri.passport.service;

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.passport.dto.DcsPayload;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.sql.Date;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.mockito.Mockito.when;
@WireMockTest(httpsPort = 8080)
@ExtendWith(MockitoExtension.class)
class PostServiceTest {

    public static final String CERT = "MIIC/TCCAeWgAwIBAgIBATANBgkqhkiG9w0BAQsFADAsMR0wGwYDVQQDDBRjcmktdWstcGFzc3BvcnQtYmFjazELMAkGA1UEBhMCR0IwHhcNMjExMjE3MTEwNTM5WhcNMjIxMjE3MTEwNTM5WjAsMR0wGwYDVQQDDBRjcmktdWstcGFzc3BvcnQtYmFjazELMAkGA1UEBhMCR0IwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDYIxWKwYNoz2MIDvYb2ip4nhCOGUccufIqwSHXl5FBOoOxOZh1rV57sWhdKO/hyZYbF5YUYTwzV4rW7DgLkfx0sN/p5igk74BZRSXvV/s+XCkVC5c0NDhNGh6WK5rc8Qbm0Ad5vEO1JpQih5y2mPGCwfLBqcY8AC7fwZinP/4YoMTCtEk5ueA0HwZLHXOEMWl/QCkj7WlSBL4i6ozk4So3RFL4awYP6nvhY7OLAcad7g/ZW0dXvztPOJnT9rwi1p6BNoD/Zk6jMJHhbvKyGsluUy7PYVGYCQ36Uuzby2Jq8cG5qNS+CBjy0/d/RmrClKd7gcnLY/J5NOC+YSynoHXRAgMBAAGjKjAoMA4GA1UdDwEB/wQEAwIFoDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDBDANBgkqhkiG9w0BAQsFAAOCAQEAvHT2AGTymh02A9HWrnGm6PEXx2Ye3NXV9eJNU1z6J298mS2kYq0Z4D0hj9i8+IoCQRbWOxLTAWBNt/CmH7jWltE4uqoAwTZD6mDgkC2eo5dY+RcuydsvJNfTcvUOyi47KKGGEcddfLti4NuX51BQIY5vSBfqZXt8+y28WuWqBMh6eny2wJtxNHo20wQei5g7w19lqwJu2F+l/ykX9K5DHjhXqZUJ77YWmY8sy/WROLjOoZZRy6YuzV8S/+c/nsPzqDAkD4rpWwASjsEDaTcH22xpGq5XUAf1hwwNsuiyXKGUHCxafYYS781LR8pLg6DpEAgcn8tBbq6MoiEGVeOp7Q==";

    private PostService postService ;

    @Mock ConfigurationService mockConfigurationService;

    @BeforeEach
    void setUp() throws CertificateException {
        postService =
            new PostService(mockConfigurationService);
        when(mockConfigurationService.getPassportPostUri()).thenReturn(
            "https://localhost:8080/checks/passport");
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        when(mockConfigurationService.getDcsTlsCert()).thenReturn(certificateFactory.generateCertificate(new ByteArrayInputStream(
            Base64.getDecoder().decode(CERT))));
    }

    @Test
    void shouldPostSucessfully(WireMockRuntimeInfo wmRuntimeInfo)
        throws UnrecoverableKeyException, CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, KeyManagementException {

        DcsPayload dcsPayload = new DcsPayload(UUID.randomUUID(), UUID.randomUUID(), Timestamp.from(Instant.now()), "1234",
                "Any", new String[]{"Any"}, Date.valueOf("1999-12-12"), Date.valueOf("2010-10-10"));

        stubFor(
                post("/checks/passport")
                        .willReturn(
                                aResponse()
                                        .withHeader("Content-Type", "application/jose")
                                        .withBody(
                                                "{}")));

        postService.postToDcs("any", dcsPayload);


       /* CredentialIssuerRequestDto credentialIssuerRequestDto =
                new CredentialIssuerRequestDto(
                        "1234",
                        "cred_issuer_id_1",
                        TEST_IPV_SESSION_ID,
                        "http://www.example.com/redirect");
        CredentialIssuerConfig credentialIssuerConfig =
                getStubCredentialIssuerConfig(wmRuntimeInfo);

        AccessToken accessToken =
                credentialIssuerService.exchangeCodeForToken(
                        credentialIssuerRequestDto, credentialIssuerConfig);
        AccessTokenType type = accessToken.getType();
        assertEquals("Bearer", type.toString());
        assertEquals(3600, accessToken.getLifetime());
        assertEquals("d09rUXQZ-4AjT6DNsRXj00KBt7Pqh8tFXBq8ul6KYQ4", accessToken.getValue());*/
    }


}