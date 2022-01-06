package uk.gov.di.ipv.cri.passport.service;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.ParseException;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DcsEncryptionServiceTest {

    public static final String BASE64_PUBLIC_CERT =
            "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZEakNDQXZZQ0NRQ3JjK3ppU2ZNeUR6QU5CZ2txaGtpRzl3MEJBUXNGQURCSk1Rc3dDUVlEVlFRR0V3SkgKUWpFTk1Bc0dBMVVFQ0F3RVZHVnpkREVOTUFzR0ExVUVCd3dFVkdWemRERU5NQXNHQTFVRUNnd0VWRVZ6ZERFTgpNQXNHQTFVRUN3d0VWR1Z6ZERBZUZ3MHlNVEV5TWpNeE1EVTJNakZhRncweU1qRXlNak14TURVMk1qRmFNRWt4CkN6QUpCZ05WQkFZVEFrZENNUTB3Q3dZRFZRUUlEQVJVWlhOME1RMHdDd1lEVlFRSERBUlVaWE4wTVEwd0N3WUQKVlFRS0RBUlVSWE4wTVEwd0N3WURWUVFMREFSVVpYTjBNSUlDSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQWc4QQpNSUlDQ2dLQ0FnRUF3RnJkUzhFUUNLaUQxNXJ1UkE3SFd5T0doeVZ0TlphV3JYOUVGZWNJZTZPQWJCRHhHS2NQCkJLbVJVMDNud3g1THppRWhNL2NlNWw0a3lTazcybFgwYSt6ZTVkb2pqZkx6dFJZcGdiSTlEYUVwMy9GTEdyWkoKRmpPZCtwaU9JZ1lBQms0YTVNdlBuOVlWeEpzNlh2aVFOZThJZVN6Y2xMR1dNV0dXOFRFTnBaMWJwRkNxa2FiRQpTN0cvdUVNMGtkaGhnYVpnVXhpK1JZUUhQcWhtNk1PZGdScWJpeTIxUDBOSFRFVktyaWtZanZYZXdTQnFtZ0xVClBRaTg1ME9qczF3UGRZVFRoajVCT2JZd3o5aEpWbWJIVEhvUGgwSDRGZGphMW9wY1M1ZXRvSGtOWU95MzdTbzgKQ2tzVjZzNnVyN3pVcWE5RlRMTXJNVnZhN2pvRHRzV2JXSjhsM2pheS9PSEV3UlI5RFNvTHVhYlppK2tWekZGUwp2eGRDTU52VzJEMmNSdzNHWW1HMGk4cXMxMXRsalFMTEV0S2EyWXJBZERSRXlFUFlKR1NYSjJDUXhqbGRpMzYrCmlHYitzNkExWVNCNzRxYldkbVcxWktqcGFPZmtmclRBZ3FocUc5UURrd2hPSk5CblVDUTBpZVpGYXV3MUZJM04KS0c1WEZSMzdKR05EL1luTGxCS1gzVzNMSGVIY1hTYUphYzYxOHFHbzgxVFduVzA2MVMzTGRVRWcyWGJ0SXJPKworNEdlNDlJbXRSTUFrcmhUUjAzMXc3ZDVnVXJtZWxCcTNzaVBmUmFkYmJ2OUM1VENHOG4zVDM1VkpLNFcybEduCkl5WUFzc09wYWxyN1Q5TmVuTzUxcUJmK2gyTjVVWitTVDV0TkYwM2s5enpKdGZORDZEcUNySHNDQXdFQUFUQU4KQmdrcWhraUc5dzBCQVFzRkFBT0NBZ0VBQWNjblhwYUNJaVNzcG5oZ0tlTk9iSm9aaUJzSWNyTU4wVU1tSmVaagpSNkM2MHQzM1lEZDhXR2VhOW91WmVUZEFYOFIxYTlZOVFtV3JMMnpUTXIwbEwxdkRleXd0eUtjTFloVmFZaHUrCi9ibVFKTjJ5TnhWdU9ONkxtbkhBUFBFdjBtc3RWM1JuQXVxYlcvTm5DU0ZkUnFsSmlYT2hRLzlQUHJUUDZzck8KT2QwVHJ6VkE3RXlQT014TjJpSUdBcTJRemFBb3B6VDFVNmF4bnpHRmZ6aTZVSGlRYURSbGhuODhGUEpNT3JMUQpyS3NlUkk4MUtIaGptZG5uOFdlWC9BaGZWSk8wejZ2TU1xRGx5QmlSUmV3VmVQcjZTejl5T2RCQVZlNFUzSDdHCmdDV3p2akEzYkxjZEpobUw4dHQvVFpFcndMblFDd2Izc3pMODNSSDl0dXIzaWdwQnJoUzlWWnM4ZldyeWY0MDgKNnU0dWd3Y1luT0NpaGtwMk9ESjVtOThCbmdZem1wT2NDZW1KTkg3WkJ1SWhDVkNjRitCejlBbTlRSjJXdzdFZApTeGNDcFQxY0hSd29Fd0I5a01ORmtpYlkzbFJBQ3BtTmQ3SWpWUU5ZNTlmeFBBdGo4cFlSYWJGa2JhSUtkT2FwCkxySE1jbmRCTXpMYkk1bGl1a2hQUTlGLyt5QkMybVRRZ0MvVzU5dThraW4yQTFRbDJRWUNXQzFYVWFXaXFxRVUKbVQ5SjU5L0dKZ3hIT1pNSXB4OERDK0ZYRDZkbEF1bUJLZzcxZnpsdjdNb3dKWWFFcFJEUlJubjU0YnQ4UmpVRwpRREpBV1VseHluSlF0dCtqdmFNR0lSZ2M2RkdJcUVVV1VzUU9wUDEwNFg4dUtPQWNSTjlmMWNSSGxTeUErTUp5Cnd1UT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=";
    public static final String BASE64_PRIVATE_KEY =
            "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";

    @Mock ConfigurationService configurationService;

    private DcsEncryptionService underTest;

    @BeforeEach
    void setUp() {
        underTest = new DcsEncryptionService(configurationService);
    }

    @Test
    void shouldEncryptStringWithCertificate()
            throws CertificateException, JOSEException, NoSuchAlgorithmException,
                    InvalidKeySpecException, ParseException {
        when(configurationService.getDcsEncryptionCert()).thenReturn(getCertificate());
        String payload = "test";
        String encryptPayload = underTest.encrypt(payload);
        assertEquals(payload, decryptPayload(encryptPayload));
    }

    @Test
    void shouldDecryptStringWithPrivateKey() throws CertificateException, JOSEException, ParseException, NoSuchAlgorithmException, InvalidKeySpecException {
        when(configurationService.getPassportCriPrivateKey()).thenReturn(getPrivateKey());

        JWSObject jwsObject = getSignedJWSObject("Hello");

        String encrypted = encryptPayload(jwsObject.serialize());

        JWSObject decrypted = underTest.decrypt(encrypted);
        assertEquals(jwsObject.getPayload().toString(), decrypted.getPayload().toString());
    }

    private JWSObject getSignedJWSObject(String payload) throws JOSEException, InvalidKeySpecException, NoSuchAlgorithmException {
        JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256).build();
        JWSObject jwsObject = new JWSObject(jwsHeader, new Payload(payload));
        jwsObject.sign(
                new RSASSASigner(getPrivateKey()));
        return jwsObject;
    }

    private String encryptPayload(String encryptedPayload)
            throws JOSEException, CertificateException {
        JWEHeader header =
                new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128CBC_HS256)
                        .type(new JOSEObjectType("JWE"))
                        .build();
        JWEObject jwe = new JWEObject(header, new Payload(encryptedPayload));

        jwe.encrypt(new RSAEncrypter((RSAPublicKey) getCertificate().getPublicKey()));

        return jwe.serialize();
    }

    private String decryptPayload(String encrypt)
            throws InvalidKeySpecException, NoSuchAlgorithmException, ParseException,
                    JOSEException {
        RSADecrypter rsaDecrypter = new RSADecrypter(getPrivateKey());

        JWEObject jweObject = JWEObject.parse(encrypt);
        jweObject.decrypt(rsaDecrypter);
        return jweObject.getPayload().toString();
    }

    private PrivateKey getPrivateKey() throws InvalidKeySpecException, NoSuchAlgorithmException {
        return KeyFactory.getInstance("RSA")
                .generatePrivate(
                        new PKCS8EncodedKeySpec(Base64.getDecoder().decode(BASE64_PRIVATE_KEY)));
    }

    private Certificate getCertificate() throws CertificateException {
        byte[] binaryCertificate = Base64.getDecoder().decode(BASE64_PUBLIC_CERT);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return factory.generateCertificate(new ByteArrayInputStream(binaryCertificate));
    }
}
