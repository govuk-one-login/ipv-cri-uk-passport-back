package uk.gov.di.ipv.cri.passport.service;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.GetPublicKeyResult;
import com.amazonaws.services.kms.model.SignResult;
import com.google.gson.Gson;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.passport.domain.Thumbprints;
import uk.gov.di.ipv.cri.passport.signing.KmsSigner;

@ExtendWith(MockitoExtension.class)
class SigningServiceTest {

    private final String cert = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDopXhLVqutlOJ9JtGhcaiwY9+8kLZhIYPk4PWxk3j8YNe3NlEtZn8NA5aNxKzRrjkYznsqbiA3NAaMSYdXobDlCH0U+/9LG63u9Ilptrx/q4ev34TdfLJ64QkPwGuKP/xRDBvAfrDPu40KGSwc03VR5YTsFon84U8g8zfo85ex9wIDAQAB";
    private final GetPublicKeyResult publicKeyResult = new GetPublicKeyResult();
    private final ByteBuffer byteBuffer = ByteBuffer.wrap(cert.getBytes(StandardCharsets.UTF_8));
    @Mock
    ConfigurationService configurationService;

    @Mock
    AWSKMS kmsClient;

    @Mock
    SignResult signResult;

    @Test
    void shouldReturnASignedJWTWhenPassedAJsonString()
        throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException, JOSEException, ParseException {

        publicKeyResult.setPublicKey(byteBuffer);

        when(configurationService.makeThumbprints()).thenReturn(new Thumbprints("asda", "asda"));
        when(configurationService.getDcsSigningKey()).thenReturn(publicKeyResult);
        when(signResult.getSignature()).thenReturn(byteBuffer);
        when(kmsClient.sign(any())).thenReturn(signResult);

        SigningService signingService = new SigningService(configurationService,
            new KmsSigner("keyId", kmsClient));

        String serializedSignedObject = signingService.signData(new Gson().toJson("test"));

        JWSObject parsedJWSObject = JWSObject.parse(serializedSignedObject);

        RSAPublicKey rsaPublic =
            (RSAPublicKey)
                KeyFactory.getInstance("RSA")
                    .generatePublic(
                        new X509EncodedKeySpec(publicKeyResult.getPublicKey().array()));
        JWSVerifier verifier = new RSASSAVerifier(rsaPublic);

        assertTrue(parsedJWSObject.verify(verifier));

    }
}
