package uk.gov.di.ipv.cri.passport.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.passport.domain.Thumbprints;
import uk.gov.di.ipv.cri.passport.utils.TestUtils;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.text.ParseException;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DcsSigningServiceTest {

    public static final String BASE64_PRIVATE_KEY =
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDMUiC17ZaXozJZBH5N2Vsqdy+b8Vq1q043cZi9BxL4BAL9gkdqFI9HCiOxskqKQXE96jt/u6h4d1EECfrpM/pwVBXVnM8iKukUP62+SsrPdG+jgP+QVB6xTJkYuKV9nd1akgdVjiHQOnx3v03+OInhdhmTP7ob9nvUuLHFtM6xRKRFooGrELRnOpJRV4GsAWXjCHPyOzHNv2Ipk08v9VZfEIlCjHnHPC+pVSF5E4p2dOp0OKsKRQBFG5al9f4BP5y1Qw2z1mJgJV1w5QElGNgNACFKAR959b7rk1JxqPVaFwWe7T/XL+xFD0VrZNEUrozNl48sRXtiwxJU/yDj3J91AgMBAAECggEBALgss8WqQ5uuhNzO+xcrfU0bIHQ+LBkkMJ4zrI1/ye58l0Fy5PLPU5OipSgxYZWchfpcoIN0YdktHH86i80YiIAmm4PxFJlk+rLA79lfS8+S0msdBcFQwlXpiPtKvgosefKBPVE2jG5JuharAB/PUSJFtaoQwK8iEN9gGQbxA3uvmeWWQvxjPuC0/C/Bm2Tm+x5UrvfflqNRXXL3X/QkhU1ZHH/577w3Meua/wPcWVc7kUWhD3pMZDGM//uyYRQezC5oDKMtYAyN/YyiuF4oB3h8wiNtI54/px/caIJWzVk+zg1hqVTByG/MRWYqKIFVhzd58HfUi4vSB/1WR+PLoqECgYEA9PwZGTqqC2Mn9A3gHW882Go+rN/Owc+cOk4Z/C4ho9uh5v2EqaKPMDZkAY1E+FFThQej8ojrVIxoUK9gSQgpa+qOobDsgGrWVSqiP8u0L4M+Xn3Fg5MGquJ0voZ8t6CbdC+u7CV/RgtUnspGm3JgsARO8pOT4LCmwxzbdmDG+ikCgYEA1YH3cOmbd39cVMGE9YGYQF1ujEttkzCKOnfZHbUeOPSnx7FypKOMFaMig9NebsSzzyE2MtIDnm04D8ddnYtIA/y1Lho11rweo9SZ6hfSWU+xENABj9lY54hvQtuWmm9Hqi/BRdRaXncJOX9iQm252I1st+yiE2hM43YmcV2+vG0CgYAWfvfHC04GEarfjE6iJU7PCKKMuViBD5FnATj9oTbRlx982JbQBO9lG/l+8vv8WWtz8cmqQcxqTSJfFlufGTLEiBtk2Zw+BpF77JhNh2UaX9DgWGhEtsGL+5OA01SsgAEGYEKNyLuxMOUqV6S4LX6Xay3ctJSFs3L8w6+bZTOgUQKBgDWlgVnyqKie7MEzGshhNrM9hrBjp3WrZaAJSxmGz8A54QpxEMBDg8hQBDUhYAHvFMr/qlGcqWIeSU7VpjUWsRKnZZLe7RY2kHBT1BSYxbbBKllyGmJdl1Qd2O7wo+fL/DLL6wEzuT0xJbU3x6WvUloSNvYD1DmSJHem0UP87RcFAoGAS3Ucq788OvYge2a06J+SShSBWgG6cuMUwU+NUmsfAqjWQTDSdG63Atrb6jXC/r2gtZuuZSIXukRfKY1pLTrNpOaNfb/S8RWXIR/x6x88GZoMn00u9S+j+c3vzlRfJO2aOiOuClxDta+npCSK4NNna5BuJa/Cr7UewRm4U8D8oWM=";
    public static final String BASE64_TEST_DCS_SIGNING_CERT =
            "MIIEOzCCAyOgAwIBAgIQEaBxBhugEhtaBJhkdFQ3MzANBgkqhkiG9w0BAQsFADBTMQswCQYDVQQGEwJHQjEXMBUGA1UEChMOQ2FiaW5ldCBPZmZpY2UxDDAKBgNVBAsTA0dEUzEdMBsGA1UEAxMUSURBUCBDb3JlIFRlc3QgQ0EgRzMwHhcNMjAxMTEwMDAwMDAwWhcNMjExMTEwMjM1OTU5WjBkMQswCQYDVQQGEwJHQjEXMBUGA1UEChQOQ2FiaW5ldCBPZmZpY2UxDDAKBgNVBAsUA0dEUzEuMCwGA1UEAxMlRENTIE5vbi1Qcm9kIFNpZ25pbmcgKDIwMjAxMTEwMTAxMDIxKTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPUumr/F/0y3MVK61NuCfPJYzX8YLg2Egv6BMgbaEtbc3qiBoCjvqLMrdcapKnSd2ytAF/RnbWAnvLtXvrbB+amNh5qZvpHuhFP01VJjboSO/PYlJnI3/oJpxvgqRDu9yk0+4f08KSOM80iK+oohRFKd6k9GKQIHU/C/46vzvixjXmdZUavqOatUxP7hdvBbX8iSbCTtnKYp1YywbpvSKKJ1xevZFkp8YFVr5y6T18d8HGY2VaMwnNW/VM/h+XNk4a7YDowl67Mrk9GnuUoKiTOO14a+8wvOYpfwkpwg1h9yDK5RE3li641mqXFU6X2UY9XY9MGDBqUVL9rATVriRmECAwEAAaOB+TCB9jAMBgNVHRMBAf8EAjAAMFsGA1UdHwRUMFIwUKBOoEyGSmh0dHA6Ly9vbnNpdGVjcmwudHJ1c3R3aXNlLmNvbS9DYWJpbmV0T2ZmaWNlSURBUENvcmVUZXN0Q0FHMy9MYXRlc3RDUkwuY3JsMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQU7Zu5g+Why/Ny+4WUXAGcY0AkChowHwYDVR0jBBgwFoAUgOspqZh/pDVP9CWMaHTeN85gLncwOQYIKwYBBQUHAQEELTArMCkGCCsGAQUFBzABhh1odHRwOi8vc3RkLW9jc3AudHJ1c3R3aXNlLmNvbTANBgkqhkiG9w0BAQsFAAOCAQEAUsKRGzneXobPX5herHlfyi4pDTAqRgskY8i+bXb4APee3ZaGX173FVIu6NkRcROajR/gxvjahvVkJAGPxjP1FDVUX4154BAda7ewBdgCblHoLsyUnY5XqDPda96VJD9prADgjISHqXVkvGo2LJG1QRPgwOV5tcPwBLlQ/7Y6UyKNo9R7qCiV3MFA0h6l3m2IeeWiiHBUuhXKhr076fKNOJB/gY8zgPOXGSu1+ipkrj/mmuHzjMjAsa1ipA3WRBuE22s9veuSYzu3FvtWMIRT/is4LpL3zijPMBezyTz3rB+8944brPFYjslsiHHSLQ//LwqRi/grVOCjnV7hZAQEIg==";
    public static final String SHA_1_THUMBPRINT = "hello";
    public static final String SHA_256_THUMBPRINT = "hello2";

    @Mock ConfigurationService configurationService;
    private DcsSigningService underTest;

    @BeforeEach
    void setUp() {
        underTest = new DcsSigningService(configurationService);
    }

    @SuppressWarnings("deprecation")
    @Test
    void shouldSignProvidedStringWithKeyAndProtectedHeaders()
            throws ParseException, NoSuchAlgorithmException, InvalidKeySpecException, JOSEException,
                    CertificateException {
        when(configurationService.getPassportCriSigningKey()).thenReturn(getSigningPrivateKey());
        when(configurationService.makeThumbprints())
                .thenReturn(new Thumbprints(SHA_1_THUMBPRINT, SHA_256_THUMBPRINT));

        String stringToSign = "String to Sign";
        JWSObject jwsObject = underTest.signData(stringToSign);
        JWSObject parsedJWSObject = JWSObject.parse(jwsObject.serialize());

        JWSVerifier verifier =
                new RSASSAVerifier((RSAPublicKey) getPublicKey(getSigningPrivateKey()));

        assertTrue(parsedJWSObject.verify(verifier));
        assertEquals("RS256", parsedJWSObject.getHeader().getAlgorithm().toString());
        assertEquals(
                SHA_1_THUMBPRINT, parsedJWSObject.getHeader().getX509CertThumbprint().toString());
        assertEquals(
                SHA_256_THUMBPRINT,
                parsedJWSObject.getHeader().getX509CertSHA256Thumbprint().toString());
    }

    @Test
    void shouldValidateOuterSignature() throws CertificateException, ParseException, JOSEException {
        when(configurationService.getDcsSigningCert())
                .thenReturn(TestUtils.getDcsSigningCertificate(BASE64_TEST_DCS_SIGNING_CERT));

        String response =
                "eyJhbGciOiJSUzI1NiJ9.ZXlKaGJHY2lPaUpTVTBFdFQwRkZVQzB5TlRZaUxDSmxibU1pT2lKQk1USTRRMEpETFVoVE1qVTJJaXdpZEhsd0lqb2lTbGRGSW4wLk5POFVpZ3p5Vl85dUV6Yi1uQUFXeENsZTFhRno0eVpWNVBQcUt2dnlydkdudDJFdjdudGxzZHY3Vkd0SGJ1UHdqdE96d25qdC1hRHhablpMcmc5aVhEbmRiRUNFZldwUTR6bXVFQkphdy0xb2hYVTFWWmlhVjZoZ0VIVmlDX3dFblJsbUlZSjJlWTZiQzQ1NEVzMGRxNEtaY3hnRTN1ZkRYdHYyX3lnbFpfUjNqUEFCNFhxY1Qyb1lKMUtrNjczLWxfbmtNS2tJX2pvbXZTcGtzN1ByNENJTWRDS2FUd2V4V1FTUVBPeVIxWm05ZnFlc3d4aEEzYjRWTEVILXZpOGRGRks4aExqOGo0akpOVW1NVHRHb2FNbGVranFEN052RWdWLUFYbVp5d296S0VQazRrZkYwbXpaUm1CeG5zdmJscjUtZ2tJOHE3OUNNMzdzellqVHRnUS5mSFFiU0xUd1JwdjJPa1dkNG5abGdBLkI2Mnh3eVJ5MlVEdW02T2VZZXd6MWhDVWk2OW9jaEdGM3NuR195aWhDMUROaDNfdU9vRW1Leks1WHhnRlc4Q1FyWHpIaktxeWRtc2hKcFBwS0M4d3Y2THhrR2hYN1JQY2JpQ0s1NnhBZ0V6blJkZGV2SWFtQkhoYUZiWEJGMXJoN2lnanRjdTJ1YVRKLURTY1FESTlFOG1NLVVYcTJkZk1RR0tvYllZRk5mOVVOck5xWXV5RFF4Z3I4RFVOM0l0MTAtbFF4eUpSTHVBQmEydklfR2Z1dVM2Y2dMV2FIRGY0TjAtencwMWxXNS02R0ZFeDVuTDc3TEtoX1czNC1TWG5xTkNzSU9YdnN2WkRDYnhJZ2ZDTE9zYW5NbmwtcXUwVEJpbDE0TE1XMDNyS2s5MEJTdUd3SEdRY1l6VTZRck9yUDROY1dPR294cXRFdFBobVR0RW8wek5WWjFKT0lGVmpsSVpjcExYeGxqLXJQdHllUV9VMXVzZkJOa2h4VzBCVTFuNG82RkZUUndUS2VFTGpCbi1HS2JQVlMzS0x0ckE5SDRDWTlveHFGbnA1bDJqOEEySnc1ZU1FZi0zOVJaYVctVVVTN0d0Z0FJS1lTUUhUdW9fTUpmV3VPVTN6cC1nNWd6Y1Y4WGNJOVhieG5LdjU1OWxvQkhBenRWNV9BV195SS13NjUzSVpHV0NuRC0zcUdUY2diODl2TldhQlhmSlJNWTBtUVJpaUxBVVVOelhITk15QXk0SnA1Q1pKRVpjTVBfRHYtNXdvd3YyNlN2aTNOcm1sRTB1eUQ2RHpkYUVndmhxdDdOZVVzOUowY3hrRXY0azVjS0FVeU1najlCTEpYT0tUcWloeEI1Mk8ydEI5ZHVmUGlzemk2R1JERmRtb2hLQnYwOHlLa1c3WVNmNVBtX2FHX2p1ek9MQWx6bW9ZWm5rWmpzVk9HUVBHamFMNTRLV3Zady4waVg2c2MzcWNCNENWNklBR09VTDd3.TR50Vggrkin5ccopyUQ5T5U04ViIIM5RTDyhVBLN62UTu3N1xxi7gQyufiPVbO3cyIfH9KznPZ_JxRfIsCQNyKwx0II61hpAXIZHMGBhadiFAwYQEvB0l8Iwxf7nvQw-d5blPz0cVNc04z6iNUImbSDGB1LgJKRNBsgcd4CZYWFH9ipAVtqNmj1LYasWIcn8y-OIRCHbQ_wySXQxc-zyckVLT0u50jqAuhRhEFx1luuOkHBac0wFJPvRq24ntY0va8xi-xHgjbJuvI8xv7IpYpYcUUqDErFQbWiEpGo0VAbc9UXlZ-DiE_B9mYf7bNvdgq4zxmULMHXpvnPc-3TvkQ";

        String expected =
                "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwidHlwIjoiSldFIn0.NO8UigzyV_9uEzb-nAAWxCle1aFz4yZV5PPqKvvyrvGnt2Ev7ntlsdv7VGtHbuPwjtOzwnjt-aDxZnZLrg9iXDndbECEfWpQ4zmuEBJaw-1ohXU1VZiaV6hgEHViC_wEnRlmIYJ2eY6bC454Es0dq4KZcxgE3ufDXtv2_yglZ_R3jPAB4XqcT2oYJ1Kk673-l_nkMKkI_jomvSpks7Pr4CIMdCKaTwexWQSQPOyR1Zm9fqeswxhA3b4VLEH-vi8dFFK8hLj8j4jJNUmMTtGoaMlekjqD7NvEgV-AXmZywozKEPk4kfF0mzZRmBxnsvblr5-gkI8q79CM37szYjTtgQ.fHQbSLTwRpv2OkWd4nZlgA.B62xwyRy2UDum6OeYewz1hCUi69ochGF3snG_yihC1DNh3_uOoEmKzK5XxgFW8CQrXzHjKqydmshJpPpKC8wv6LxkGhX7RPcbiCK56xAgEznRddevIamBHhaFbXBF1rh7igjtcu2uaTJ-DScQDI9E8mM-UXq2dfMQGKobYYFNf9UNrNqYuyDQxgr8DUN3It10-lQxyJRLuABa2vI_GfuuS6cgLWaHDf4N0-zw01lW5-6GFEx5nL77LKh_W34-SXnqNCsIOXvsvZDCbxIgfCLOsanMnl-qu0TBil14LMW03rKk90BSuGwHGQcYzU6QrOrP4NcWOGoxqtEtPhmTtEo0zNVZ1JOIFVjlIZcpLXxlj-rPtyeQ_U1usfBNkhxW0BU1n4o6FFTRwTKeELjBn-GKbPVS3KLtrA9H4CY9oxqFnp5l2j8A2Jw5eMEf-39RZaW-UUS7GtgAIKYSQHTuo_MJfWuOU3zp-g5gzcV8XcI9XbxnKv559loBHAztV5_AW_yI-w653IZGWCnD-3qGTcgb89vNWaBXfJRMY0mQRiiLAUUNzXHNMyAy4Jp5CZJEZcMP_Dv-5wowv26Svi3NrmlE0uyD6DzdaEgvhqt7NeUs9J0cxkEv4k5cKAUyMgj9BLJXOKTqihxB52O2tB9dufPiszi6GRDFdmohKBv08yKkW7YSf5Pm_aG_juzOLAlzmoYZnkZjsVOGQPGjaL54KWvZw.0iX6sc3qcB4CV6IAGOUL7w";

        assertEquals(expected, underTest.validateOuterSignature(response));
    }

    @Test
    void shouldValidateInnerSignature() throws CertificateException, ParseException, JOSEException {
        when(configurationService.getDcsSigningCert())
                .thenReturn(TestUtils.getDcsSigningCertificate(BASE64_TEST_DCS_SIGNING_CERT));

        String decryptedPayload =
                "eyJhbGciOiJSUzI1NiJ9.eyJjb3JyZWxhdGlvbklkIjoiNTc4MmQ1MWItNWI3Mi00NDQ4LThiMDYtY2Q4NmM0NDZiYzljIiwiZXJyb3IiOmZhbHNlLCJyZXF1ZXN0SWQiOiJiNWUyY2FjNi0zM2M4LTQ2NjQtYjFmZS0yYjQ5MGZkYjFjODIiLCJ2YWxpZCI6dHJ1ZX0.Me6ZAywbIrWZ7h0ekrCFxnhYDXdOmSWQLhQiuKq0msVtd5oQLzBGVWSs3agj9mQBN3yszYm6aFABc8r93t5jidaNCyaUJJSXd0qfQoK7G4eJaxEnOzSS26oRqk8t6OYtcfTfQ3QrZsS64B7OH0AhYR76RIeVWrVLbQ3qMsFujMqYZ68A6mDbeGYIUf9Wow41urbFHVbFoP30CA86Mb-JyA53nydaiBA5glppC571Ic-RUNF4HordP2i2c3X8lKkUmWlExormra4cXNEzDnaEbrRRTMSwcixTkpMWvDIN_7kqS2v9M84xBWDzxdnfS5F0UFgUDMWrrbk_dI_pQp1LgA";

        JWSObject jwsObject = JWSObject.parse(decryptedPayload);

        String expected =
                "{\"correlationId\":\"5782d51b-5b72-4448-8b06-cd86c446bc9c\",\"error\":false,\"requestId\":\"b5e2cac6-33c8-4664-b1fe-2b490fdb1c82\",\"valid\":true}";

        assertEquals(expected, underTest.validateInnerSignature(jwsObject));
    }

    private PublicKey getPublicKey(RSAPrivateKey signingPrivateKey)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        RSAPrivateCrtKey rsaPrivateCrtKey = (RSAPrivateCrtKey) signingPrivateKey;
        RSAPublicKeySpec keySpec =
                new RSAPublicKeySpec(
                        rsaPrivateCrtKey.getModulus(), rsaPrivateCrtKey.getPublicExponent());
        return KeyFactory.getInstance("RSA").generatePublic(keySpec);
    }

    private RSAPrivateKey getSigningPrivateKey()
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        return (RSAPrivateKey)
                KeyFactory.getInstance("RSA")
                        .generatePrivate(
                                new PKCS8EncodedKeySpec(
                                        Base64.getDecoder().decode(BASE64_PRIVATE_KEY)));
    }
}
