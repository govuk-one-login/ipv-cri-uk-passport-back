package uk.gov.di.ipv.cri.passport.service;

import static com.nimbusds.jose.JWSObject.State.SIGNED;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.GetPublicKeyResult;
import com.amazonaws.services.kms.model.SignResult;
import com.google.gson.Gson;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.passport.domain.Thumbprints;
import uk.gov.di.ipv.cri.passport.kms.KmsSigner;

@ExtendWith(MockitoExtension.class)
class SigningServiceTest {

    public static final String TEST_PAYLOAD = "test payload";
    private final String signingKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDopXhLVqutlOJ9JtGhcaiwY9+8kLZhIYPk4PWxk3j8YNe3NlEtZn8NA5aNxKzRrjkYznsqbiA3NAaMSYdXobDlCH0U+/9LG63u9Ilptrx/q4ev34TdfLJ64QkPwGuKP/xRDBvAfrDPu40KGSwc03VR5YTsFon84U8g8zfo85ex9wIDAQAB";
    private final GetPublicKeyResult publicKeyResult = new GetPublicKeyResult();
    private final ByteBuffer signingKeyByteBuffer = ByteBuffer.wrap(Base64.getDecoder().decode(signingKey));
    @Mock
    ConfigurationService configurationService;

    @Mock
    AWSKMS kmsClient;

    @Mock
    SignResult signResult;

    @Test
    void shouldReturnASignedJWTWhenPassedAJsonString()
        throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException, JOSEException, ParseException {

        String expectedSignature = signingKey.replace("+", "-").replace("/", "_");

        publicKeyResult.setPublicKey(signingKeyByteBuffer);

        when(configurationService.makeThumbprints()).thenReturn(new Thumbprints("test", "test"));
        when(configurationService.getDcsSigningKey()).thenReturn(publicKeyResult);
        when(signResult.getSignature()).thenReturn(signingKeyByteBuffer);
        when(kmsClient.sign(any())).thenReturn(signResult);

        SigningService signingService = new SigningService(configurationService,
            new KmsSigner("keyId", kmsClient));

        String serializedSignedObject = signingService.signData(new Gson().toJson(TEST_PAYLOAD));

        JWSObject parsedJWSObject = JWSObject.parse(serializedSignedObject);

        assertEquals(SIGNED, parsedJWSObject.getState());
        assertEquals(new Gson().toJson(TEST_PAYLOAD), parsedJWSObject.getPayload().toString());
        assertEquals(expectedSignature, parsedJWSObject.getSignature().toString());
    }

}
