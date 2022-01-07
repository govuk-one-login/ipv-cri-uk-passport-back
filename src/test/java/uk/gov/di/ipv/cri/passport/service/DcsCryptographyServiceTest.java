package uk.gov.di.ipv.cri.passport.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.cri.passport.domain.DcsPayload;
import uk.gov.di.ipv.cri.passport.domain.DcsSignedEncryptedResponse;
import uk.gov.di.ipv.cri.passport.domain.Thumbprints;
import uk.gov.di.ipv.cri.passport.utils.TestUtils;

import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.text.ParseException;
import java.time.LocalDate;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DcsCryptographyServiceTest {
    public static final String BASE64_DCS_SIGNING_CERT =
            "MIIEOzCCAyOgAwIBAgIQEaBxBhugEhtaBJhkdFQ3MzANBgkqhkiG9w0BAQsFADBTMQswCQYDVQQGEwJHQjEXMBUGA1UEChMOQ2FiaW5ldCBPZmZpY2UxDDAKBgNVBAsTA0dEUzEdMBsGA1UEAxMUSURBUCBDb3JlIFRlc3QgQ0EgRzMwHhcNMjAxMTEwMDAwMDAwWhcNMjExMTEwMjM1OTU5WjBkMQswCQYDVQQGEwJHQjEXMBUGA1UEChQOQ2FiaW5ldCBPZmZpY2UxDDAKBgNVBAsUA0dEUzEuMCwGA1UEAxMlRENTIE5vbi1Qcm9kIFNpZ25pbmcgKDIwMjAxMTEwMTAxMDIxKTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPUumr/F/0y3MVK61NuCfPJYzX8YLg2Egv6BMgbaEtbc3qiBoCjvqLMrdcapKnSd2ytAF/RnbWAnvLtXvrbB+amNh5qZvpHuhFP01VJjboSO/PYlJnI3/oJpxvgqRDu9yk0+4f08KSOM80iK+oohRFKd6k9GKQIHU/C/46vzvixjXmdZUavqOatUxP7hdvBbX8iSbCTtnKYp1YywbpvSKKJ1xevZFkp8YFVr5y6T18d8HGY2VaMwnNW/VM/h+XNk4a7YDowl67Mrk9GnuUoKiTOO14a+8wvOYpfwkpwg1h9yDK5RE3li641mqXFU6X2UY9XY9MGDBqUVL9rATVriRmECAwEAAaOB+TCB9jAMBgNVHRMBAf8EAjAAMFsGA1UdHwRUMFIwUKBOoEyGSmh0dHA6Ly9vbnNpdGVjcmwudHJ1c3R3aXNlLmNvbS9DYWJpbmV0T2ZmaWNlSURBUENvcmVUZXN0Q0FHMy9MYXRlc3RDUkwuY3JsMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQU7Zu5g+Why/Ny+4WUXAGcY0AkChowHwYDVR0jBBgwFoAUgOspqZh/pDVP9CWMaHTeN85gLncwOQYIKwYBBQUHAQEELTArMCkGCCsGAQUFBzABhh1odHRwOi8vc3RkLW9jc3AudHJ1c3R3aXNlLmNvbTANBgkqhkiG9w0BAQsFAAOCAQEAUsKRGzneXobPX5herHlfyi4pDTAqRgskY8i+bXb4APee3ZaGX173FVIu6NkRcROajR/gxvjahvVkJAGPxjP1FDVUX4154BAda7ewBdgCblHoLsyUnY5XqDPda96VJD9prADgjISHqXVkvGo2LJG1QRPgwOV5tcPwBLlQ/7Y6UyKNo9R7qCiV3MFA0h6l3m2IeeWiiHBUuhXKhr076fKNOJB/gY8zgPOXGSu1+ipkrj/mmuHzjMjAsa1ipA3WRBuE22s9veuSYzu3FvtWMIRT/is4LpL3zijPMBezyTz3rB+8944brPFYjslsiHHSLQ//LwqRi/grVOCjnV7hZAQEIg==";
    public static final String BASE64_SIGNING_PRIVATE_KEY =
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDMUiC17ZaXozJZBH5N2Vsqdy+b8Vq1q043cZi9BxL4BAL9gkdqFI9HCiOxskqKQXE96jt/u6h4d1EECfrpM/pwVBXVnM8iKukUP62+SsrPdG+jgP+QVB6xTJkYuKV9nd1akgdVjiHQOnx3v03+OInhdhmTP7ob9nvUuLHFtM6xRKRFooGrELRnOpJRV4GsAWXjCHPyOzHNv2Ipk08v9VZfEIlCjHnHPC+pVSF5E4p2dOp0OKsKRQBFG5al9f4BP5y1Qw2z1mJgJV1w5QElGNgNACFKAR959b7rk1JxqPVaFwWe7T/XL+xFD0VrZNEUrozNl48sRXtiwxJU/yDj3J91AgMBAAECggEBALgss8WqQ5uuhNzO+xcrfU0bIHQ+LBkkMJ4zrI1/ye58l0Fy5PLPU5OipSgxYZWchfpcoIN0YdktHH86i80YiIAmm4PxFJlk+rLA79lfS8+S0msdBcFQwlXpiPtKvgosefKBPVE2jG5JuharAB/PUSJFtaoQwK8iEN9gGQbxA3uvmeWWQvxjPuC0/C/Bm2Tm+x5UrvfflqNRXXL3X/QkhU1ZHH/577w3Meua/wPcWVc7kUWhD3pMZDGM//uyYRQezC5oDKMtYAyN/YyiuF4oB3h8wiNtI54/px/caIJWzVk+zg1hqVTByG/MRWYqKIFVhzd58HfUi4vSB/1WR+PLoqECgYEA9PwZGTqqC2Mn9A3gHW882Go+rN/Owc+cOk4Z/C4ho9uh5v2EqaKPMDZkAY1E+FFThQej8ojrVIxoUK9gSQgpa+qOobDsgGrWVSqiP8u0L4M+Xn3Fg5MGquJ0voZ8t6CbdC+u7CV/RgtUnspGm3JgsARO8pOT4LCmwxzbdmDG+ikCgYEA1YH3cOmbd39cVMGE9YGYQF1ujEttkzCKOnfZHbUeOPSnx7FypKOMFaMig9NebsSzzyE2MtIDnm04D8ddnYtIA/y1Lho11rweo9SZ6hfSWU+xENABj9lY54hvQtuWmm9Hqi/BRdRaXncJOX9iQm252I1st+yiE2hM43YmcV2+vG0CgYAWfvfHC04GEarfjE6iJU7PCKKMuViBD5FnATj9oTbRlx982JbQBO9lG/l+8vv8WWtz8cmqQcxqTSJfFlufGTLEiBtk2Zw+BpF77JhNh2UaX9DgWGhEtsGL+5OA01SsgAEGYEKNyLuxMOUqV6S4LX6Xay3ctJSFs3L8w6+bZTOgUQKBgDWlgVnyqKie7MEzGshhNrM9hrBjp3WrZaAJSxmGz8A54QpxEMBDg8hQBDUhYAHvFMr/qlGcqWIeSU7VpjUWsRKnZZLe7RY2kHBT1BSYxbbBKllyGmJdl1Qd2O7wo+fL/DLL6wEzuT0xJbU3x6WvUloSNvYD1DmSJHem0UP87RcFAoGAS3Ucq788OvYge2a06J+SShSBWgG6cuMUwU+NUmsfAqjWQTDSdG63Atrb6jXC/r2gtZuuZSIXukRfKY1pLTrNpOaNfb/S8RWXIR/x6x88GZoMn00u9S+j+c3vzlRfJO2aOiOuClxDta+npCSK4NNna5BuJa/Cr7UewRm4U8D8oWM=";
    public static final String BASE64_ENCRYPTION_PUBLIC_CERT =
            "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZEakNDQXZZQ0NRQ3JjK3ppU2ZNeUR6QU5CZ2txaGtpRzl3MEJBUXNGQURCSk1Rc3dDUVlEVlFRR0V3SkgKUWpFTk1Bc0dBMVVFQ0F3RVZHVnpkREVOTUFzR0ExVUVCd3dFVkdWemRERU5NQXNHQTFVRUNnd0VWRVZ6ZERFTgpNQXNHQTFVRUN3d0VWR1Z6ZERBZUZ3MHlNVEV5TWpNeE1EVTJNakZhRncweU1qRXlNak14TURVMk1qRmFNRWt4CkN6QUpCZ05WQkFZVEFrZENNUTB3Q3dZRFZRUUlEQVJVWlhOME1RMHdDd1lEVlFRSERBUlVaWE4wTVEwd0N3WUQKVlFRS0RBUlVSWE4wTVEwd0N3WURWUVFMREFSVVpYTjBNSUlDSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQWc4QQpNSUlDQ2dLQ0FnRUF3RnJkUzhFUUNLaUQxNXJ1UkE3SFd5T0doeVZ0TlphV3JYOUVGZWNJZTZPQWJCRHhHS2NQCkJLbVJVMDNud3g1THppRWhNL2NlNWw0a3lTazcybFgwYSt6ZTVkb2pqZkx6dFJZcGdiSTlEYUVwMy9GTEdyWkoKRmpPZCtwaU9JZ1lBQms0YTVNdlBuOVlWeEpzNlh2aVFOZThJZVN6Y2xMR1dNV0dXOFRFTnBaMWJwRkNxa2FiRQpTN0cvdUVNMGtkaGhnYVpnVXhpK1JZUUhQcWhtNk1PZGdScWJpeTIxUDBOSFRFVktyaWtZanZYZXdTQnFtZ0xVClBRaTg1ME9qczF3UGRZVFRoajVCT2JZd3o5aEpWbWJIVEhvUGgwSDRGZGphMW9wY1M1ZXRvSGtOWU95MzdTbzgKQ2tzVjZzNnVyN3pVcWE5RlRMTXJNVnZhN2pvRHRzV2JXSjhsM2pheS9PSEV3UlI5RFNvTHVhYlppK2tWekZGUwp2eGRDTU52VzJEMmNSdzNHWW1HMGk4cXMxMXRsalFMTEV0S2EyWXJBZERSRXlFUFlKR1NYSjJDUXhqbGRpMzYrCmlHYitzNkExWVNCNzRxYldkbVcxWktqcGFPZmtmclRBZ3FocUc5UURrd2hPSk5CblVDUTBpZVpGYXV3MUZJM04KS0c1WEZSMzdKR05EL1luTGxCS1gzVzNMSGVIY1hTYUphYzYxOHFHbzgxVFduVzA2MVMzTGRVRWcyWGJ0SXJPKworNEdlNDlJbXRSTUFrcmhUUjAzMXc3ZDVnVXJtZWxCcTNzaVBmUmFkYmJ2OUM1VENHOG4zVDM1VkpLNFcybEduCkl5WUFzc09wYWxyN1Q5TmVuTzUxcUJmK2gyTjVVWitTVDV0TkYwM2s5enpKdGZORDZEcUNySHNDQXdFQUFUQU4KQmdrcWhraUc5dzBCQVFzRkFBT0NBZ0VBQWNjblhwYUNJaVNzcG5oZ0tlTk9iSm9aaUJzSWNyTU4wVU1tSmVaagpSNkM2MHQzM1lEZDhXR2VhOW91WmVUZEFYOFIxYTlZOVFtV3JMMnpUTXIwbEwxdkRleXd0eUtjTFloVmFZaHUrCi9ibVFKTjJ5TnhWdU9ONkxtbkhBUFBFdjBtc3RWM1JuQXVxYlcvTm5DU0ZkUnFsSmlYT2hRLzlQUHJUUDZzck8KT2QwVHJ6VkE3RXlQT014TjJpSUdBcTJRemFBb3B6VDFVNmF4bnpHRmZ6aTZVSGlRYURSbGhuODhGUEpNT3JMUQpyS3NlUkk4MUtIaGptZG5uOFdlWC9BaGZWSk8wejZ2TU1xRGx5QmlSUmV3VmVQcjZTejl5T2RCQVZlNFUzSDdHCmdDV3p2akEzYkxjZEpobUw4dHQvVFpFcndMblFDd2Izc3pMODNSSDl0dXIzaWdwQnJoUzlWWnM4ZldyeWY0MDgKNnU0dWd3Y1luT0NpaGtwMk9ESjVtOThCbmdZem1wT2NDZW1KTkg3WkJ1SWhDVkNjRitCejlBbTlRSjJXdzdFZApTeGNDcFQxY0hSd29Fd0I5a01ORmtpYlkzbFJBQ3BtTmQ3SWpWUU5ZNTlmeFBBdGo4cFlSYWJGa2JhSUtkT2FwCkxySE1jbmRCTXpMYkk1bGl1a2hQUTlGLyt5QkMybVRRZ0MvVzU5dThraW4yQTFRbDJRWUNXQzFYVWFXaXFxRVUKbVQ5SjU5L0dKZ3hIT1pNSXB4OERDK0ZYRDZkbEF1bUJLZzcxZnpsdjdNb3dKWWFFcFJEUlJubjU0YnQ4UmpVRwpRREpBV1VseHluSlF0dCtqdmFNR0lSZ2M2RkdJcUVVV1VzUU9wUDEwNFg4dUtPQWNSTjlmMWNSSGxTeUErTUp5Cnd1UT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=";
    public static final String BASE64_ENCRYPTION_PRIVATE_KEY =
            "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";
    public static final String SHA_1_THUMBPRINT = "SHA_1_THUMBPRINT";
    public static final String SHA_256_THUMBPRINT = "SHA_256_THUMBPRINT";
    private final ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());

    @Mock ConfigurationService configurationService;
    private DcsCryptographyService underTest;

    @BeforeEach
    void setUp() {
        underTest = new DcsCryptographyService(configurationService);
    }

    @Test
    void shouldPreparePayloadForDcsRequest() throws JOSEException, InvalidKeySpecException, NoSuchAlgorithmException, CertificateException, ParseException, JsonProcessingException {
        when(configurationService.getPassportCriSigningKey()).thenReturn(getSigningPrivateKey());
        when(configurationService.makeThumbprints())
                .thenReturn(new Thumbprints(SHA_1_THUMBPRINT, SHA_256_THUMBPRINT));
        when(configurationService.getDcsEncryptionCert()).thenReturn(getEncryptionCertificate());

        DcsPayload dcsPayload = new DcsPayload("PASSPORT_NUMBER", "SURNAME", new String[] {"FORENAMES"}, LocalDate.now(), LocalDate.now());
        JWSObject preparedPayload = underTest.preparePayload(dcsPayload);

        JWSVerifier verifier =
                new RSASSAVerifier((RSAPublicKey) getSigningPublicKey(getSigningPrivateKey()));

        JWEObject encryptedContents = JWEObject.parse(preparedPayload.getPayload().toString());

        RSADecrypter rsaDecrypter = new RSADecrypter(getEncryptionPrivateKey());
        encryptedContents.decrypt(rsaDecrypter);

        JWSObject decryptedPassportDetails = JWSObject.parse(encryptedContents.getPayload().toString());

        assertTrue(decryptedPassportDetails.verify(verifier));
        String expected = objectMapper.writeValueAsString(dcsPayload);
        assertEquals(expected, decryptedPassportDetails.getPayload().toString());

    }

    @Test
    void shouldUnwrapDcsResponse() throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException, ParseException, JOSEException {
        when(configurationService.getDcsSigningCert())
                .thenReturn(TestUtils.getDcsSigningCertificate(BASE64_DCS_SIGNING_CERT));
        when(configurationService.getPassportCriPrivateKey()).thenReturn(getEncryptionPrivateKey());

        String dcsResponse =
                "eyJhbGciOiJSUzI1NiJ9.ZXlKaGJHY2lPaUpTVTBFdFQwRkZVQzB5TlRZaUxDSmxibU1pT2lKQk1USTRRMEpETFVoVE1qVTJJaXdpZEhsd0lqb2lTbGRGSW4wLk5POFVpZ3p5Vl85dUV6Yi1uQUFXeENsZTFhRno0eVpWNVBQcUt2dnlydkdudDJFdjdudGxzZHY3Vkd0SGJ1UHdqdE96d25qdC1hRHhablpMcmc5aVhEbmRiRUNFZldwUTR6bXVFQkphdy0xb2hYVTFWWmlhVjZoZ0VIVmlDX3dFblJsbUlZSjJlWTZiQzQ1NEVzMGRxNEtaY3hnRTN1ZkRYdHYyX3lnbFpfUjNqUEFCNFhxY1Qyb1lKMUtrNjczLWxfbmtNS2tJX2pvbXZTcGtzN1ByNENJTWRDS2FUd2V4V1FTUVBPeVIxWm05ZnFlc3d4aEEzYjRWTEVILXZpOGRGRks4aExqOGo0akpOVW1NVHRHb2FNbGVranFEN052RWdWLUFYbVp5d296S0VQazRrZkYwbXpaUm1CeG5zdmJscjUtZ2tJOHE3OUNNMzdzellqVHRnUS5mSFFiU0xUd1JwdjJPa1dkNG5abGdBLkI2Mnh3eVJ5MlVEdW02T2VZZXd6MWhDVWk2OW9jaEdGM3NuR195aWhDMUROaDNfdU9vRW1Leks1WHhnRlc4Q1FyWHpIaktxeWRtc2hKcFBwS0M4d3Y2THhrR2hYN1JQY2JpQ0s1NnhBZ0V6blJkZGV2SWFtQkhoYUZiWEJGMXJoN2lnanRjdTJ1YVRKLURTY1FESTlFOG1NLVVYcTJkZk1RR0tvYllZRk5mOVVOck5xWXV5RFF4Z3I4RFVOM0l0MTAtbFF4eUpSTHVBQmEydklfR2Z1dVM2Y2dMV2FIRGY0TjAtencwMWxXNS02R0ZFeDVuTDc3TEtoX1czNC1TWG5xTkNzSU9YdnN2WkRDYnhJZ2ZDTE9zYW5NbmwtcXUwVEJpbDE0TE1XMDNyS2s5MEJTdUd3SEdRY1l6VTZRck9yUDROY1dPR294cXRFdFBobVR0RW8wek5WWjFKT0lGVmpsSVpjcExYeGxqLXJQdHllUV9VMXVzZkJOa2h4VzBCVTFuNG82RkZUUndUS2VFTGpCbi1HS2JQVlMzS0x0ckE5SDRDWTlveHFGbnA1bDJqOEEySnc1ZU1FZi0zOVJaYVctVVVTN0d0Z0FJS1lTUUhUdW9fTUpmV3VPVTN6cC1nNWd6Y1Y4WGNJOVhieG5LdjU1OWxvQkhBenRWNV9BV195SS13NjUzSVpHV0NuRC0zcUdUY2diODl2TldhQlhmSlJNWTBtUVJpaUxBVVVOelhITk15QXk0SnA1Q1pKRVpjTVBfRHYtNXdvd3YyNlN2aTNOcm1sRTB1eUQ2RHpkYUVndmhxdDdOZVVzOUowY3hrRXY0azVjS0FVeU1najlCTEpYT0tUcWloeEI1Mk8ydEI5ZHVmUGlzemk2R1JERmRtb2hLQnYwOHlLa1c3WVNmNVBtX2FHX2p1ek9MQWx6bW9ZWm5rWmpzVk9HUVBHamFMNTRLV3Zady4waVg2c2MzcWNCNENWNklBR09VTDd3.TR50Vggrkin5ccopyUQ5T5U04ViIIM5RTDyhVBLN62UTu3N1xxi7gQyufiPVbO3cyIfH9KznPZ_JxRfIsCQNyKwx0II61hpAXIZHMGBhadiFAwYQEvB0l8Iwxf7nvQw-d5blPz0cVNc04z6iNUImbSDGB1LgJKRNBsgcd4CZYWFH9ipAVtqNmj1LYasWIcn8y-OIRCHbQ_wySXQxc-zyckVLT0u50jqAuhRhEFx1luuOkHBac0wFJPvRq24ntY0va8xi-xHgjbJuvI8xv7IpYpYcUUqDErFQbWiEpGo0VAbc9UXlZ-DiE_B9mYf7bNvdgq4zxmULMHXpvnPc-3TvkQ";

        String expectedPayload =
                "{\"correlationId\":\"5782d51b-5b72-4448-8b06-cd86c446bc9c\",\"error\":false,\"requestId\":\"b5e2cac6-33c8-4664-b1fe-2b490fdb1c82\",\"valid\":true}";

        DcsSignedEncryptedResponse dcsResponseItem = new DcsSignedEncryptedResponse(dcsResponse);

        assertEquals(expectedPayload, underTest.unwrapDcsResponse(dcsResponseItem));
    }

    private PublicKey getSigningPublicKey(RSAPrivateKey signingPrivateKey)
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
                                        Base64.getDecoder().decode(BASE64_SIGNING_PRIVATE_KEY)));
    }

    private PrivateKey getEncryptionPrivateKey() throws InvalidKeySpecException, NoSuchAlgorithmException {
        return KeyFactory.getInstance("RSA")
                .generatePrivate(
                        new PKCS8EncodedKeySpec(Base64.getDecoder().decode(BASE64_ENCRYPTION_PRIVATE_KEY)));
    }

    private Certificate getEncryptionCertificate() throws CertificateException {
        byte[] binaryCertificate = Base64.getDecoder().decode(BASE64_ENCRYPTION_PUBLIC_CERT);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return factory.generateCertificate(new ByteArrayInputStream(binaryCertificate));
    }

}