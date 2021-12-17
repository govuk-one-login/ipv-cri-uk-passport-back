package uk.gov.di.ipv.cri.passport.service;

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@WireMockTest(httpsPort = 8999)
class PostServiceTest {

    private ConfigurationService mockConfigurationService;
    private PostService postService ;

    @BeforeEach
    void setUp() {
        mockConfigurationService = mock(ConfigurationService.class);
        postService =
                new PostService(mockConfigurationService);
        when(mockConfigurationService.GetPassportPostUri()).thenReturn("https://localhost:8999/checks/passport");
    }

    @Test
    void shouldPostSucessfully (WireMockRuntimeInfo wmRuntimeInfo) throws UnrecoverableKeyException, CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, KeyManagementException {

        stubFor(
                post("/checks/passport")
                        .willReturn(
                                aResponse()
                                        .withHeader("Content-Type", "application/jose")
                                        .withBody(
                                                "{}")));

        postService.postToDcs("any");


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