package uk.gov.di.ipv.cri.passport.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.util.EntityUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PassportServiceTest {

    public static final String PAYLOAD = "Payload";
    public static final String SIGNED_PAYLOAD = "SignedPayload";
    public static final String ENCRYPTED_PAYLOAD = "EncryptedPayload";
    public static final String SIGNED_ENCRYPTED_PAYLOAD = "SignedEncryptedPayload";
    public static final String EXPECTED_RESPONSE = "Expected Response";
    public static final String CHECK_PASSPORT_URI = "https://localhost/check/passport";

    @Mock ConfigurationService configurationService;
    @Mock DcsSigningService dcsSigningService;
    @Mock DcsEncryptionService dcsEncryptionService;
    @Mock HttpClient httpClient;
    @Mock JWSObject jwsObject;
    @Mock JWSObject jwsObject2;
    @Mock HttpResponse httpResponse;

    @Captor ArgumentCaptor<HttpPost> httpPost;

    private PassportService underTest;

    @BeforeEach
    void setUp()
            throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException,
                    JOSEException, IOException {
        when(jwsObject.serialize()).thenReturn(SIGNED_PAYLOAD);
        when(dcsSigningService.signData(PAYLOAD)).thenReturn(jwsObject);
        when(dcsEncryptionService.encrypt(jwsObject.serialize())).thenReturn(ENCRYPTED_PAYLOAD);
        when(dcsSigningService.signData(ENCRYPTED_PAYLOAD)).thenReturn(jwsObject2);
        when(jwsObject2.serialize()).thenReturn(SIGNED_ENCRYPTED_PAYLOAD);
        when(configurationService.getDCSPostUrl()).thenReturn(CHECK_PASSPORT_URI);

        underTest =
                new PassportService(
                        httpClient, configurationService, dcsEncryptionService, dcsSigningService);
    }

    @Test
    void shouldSignEncryptSignAndPostToDcsEndpoint()
            throws IOException, CertificateException, NoSuchAlgorithmException,
                    InvalidKeySpecException, JOSEException {
        when(httpResponse.toString()).thenReturn(EXPECTED_RESPONSE);
        when(httpClient.execute(any(HttpPost.class))).thenReturn(httpResponse);

        assertEquals(EXPECTED_RESPONSE, underTest.dcsPassportCheck(PAYLOAD));

        verify(dcsSigningService, times(1)).signData(PAYLOAD); // Mock the result
        verify(dcsEncryptionService, times(1)).encrypt(jwsObject.serialize());
        verify(dcsSigningService, times(1)).signData(ENCRYPTED_PAYLOAD);
        verify(httpClient, times(1)).execute(httpPost.capture());

        assertEquals(CHECK_PASSPORT_URI, httpPost.getValue().getURI().toString());
        assertEquals(
                "application/jose", httpPost.getValue().getFirstHeader("content-type").getValue());
        assertEquals(
                SIGNED_ENCRYPTED_PAYLOAD, EntityUtils.toString(httpPost.getValue().getEntity()));
    }

    @Test
    void shouldReturnNullWhenResponseFromDcsIsNull() throws IOException {
        when(httpClient.execute(any(HttpPost.class))).thenReturn(null);
        assertNull(underTest.dcsPassportCheck(PAYLOAD));
    }
}
