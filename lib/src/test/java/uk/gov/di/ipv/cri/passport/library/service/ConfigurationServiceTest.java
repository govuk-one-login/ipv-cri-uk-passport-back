package uk.gov.di.ipv.cri.passport.library.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.lambda.powertools.parameters.SSMProvider;
import uk.gov.di.ipv.cri.passport.library.domain.Thumbprints;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;
import uk.org.webcompere.systemstubs.properties.SystemProperties;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;

import static com.github.tomakehurst.wiremock.client.WireMock.getAllServeEvents;
import static com.github.tomakehurst.wiremock.client.WireMock.ok;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

@WireMockTest(httpPort = ConfigurationService.LOCALHOST_PORT)
@ExtendWith(MockitoExtension.class)
@ExtendWith(SystemStubsExtension.class)
class ConfigurationServiceTest {

    public static final String TEST_CERT =
            "MIIC/TCCAeWgAwIBAgIBATANBgkqhkiG9w0BAQsFADAsMR0wGwYDVQQDDBRjcmktdWstcGFzc3BvcnQtYmFjazELMAkGA1UEBhMCR0IwHhcNMjExMjE3MTEwNTM5WhcNMjIxMjE3MTEwNTM5WjAsMR0wGwYDVQQDDBRjcmktdWstcGFzc3BvcnQtYmFjazELMAkGA1UEBhMCR0IwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDYIxWKwYNoz2MIDvYb2ip4nhCOGUccufIqwSHXl5FBOoOxOZh1rV57sWhdKO/hyZYbF5YUYTwzV4rW7DgLkfx0sN/p5igk74BZRSXvV/s+XCkVC5c0NDhNGh6WK5rc8Qbm0Ad5vEO1JpQih5y2mPGCwfLBqcY8AC7fwZinP/4YoMTCtEk5ueA0HwZLHXOEMWl/QCkj7WlSBL4i6ozk4So3RFL4awYP6nvhY7OLAcad7g/ZW0dXvztPOJnT9rwi1p6BNoD/Zk6jMJHhbvKyGsluUy7PYVGYCQ36Uuzby2Jq8cG5qNS+CBjy0/d/RmrClKd7gcnLY/J5NOC+YSynoHXRAgMBAAGjKjAoMA4GA1UdDwEB/wQEAwIFoDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDBDANBgkqhkiG9w0BAQsFAAOCAQEAvHT2AGTymh02A9HWrnGm6PEXx2Ye3NXV9eJNU1z6J298mS2kYq0Z4D0hj9i8+IoCQRbWOxLTAWBNt/CmH7jWltE4uqoAwTZD6mDgkC2eo5dY+RcuydsvJNfTcvUOyi47KKGGEcddfLti4NuX51BQIY5vSBfqZXt8+y28WuWqBMh6eny2wJtxNHo20wQei5g7w19lqwJu2F+l/ykX9K5DHjhXqZUJ77YWmY8sy/WROLjOoZZRy6YuzV8S/+c/nsPzqDAkD4rpWwASjsEDaTcH22xpGq5XUAf1hwwNsuiyXKGUHCxafYYS781LR8pLg6DpEAgcn8tBbq6MoiEGVeOp7Q==";
    public static final String TEST_PRIVATE_KEY =
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDMUiC17ZaXozJZBH5N2Vsqdy+b8Vq1q043cZi9BxL4BAL9gkdqFI9HCiOxskqKQXE96jt/u6h4d1EECfrpM/pwVBXVnM8iKukUP62+SsrPdG+jgP+QVB6xTJkYuKV9nd1akgdVjiHQOnx3v03+OInhdhmTP7ob9nvUuLHFtM6xRKRFooGrELRnOpJRV4GsAWXjCHPyOzHNv2Ipk08v9VZfEIlCjHnHPC+pVSF5E4p2dOp0OKsKRQBFG5al9f4BP5y1Qw2z1mJgJV1w5QElGNgNACFKAR959b7rk1JxqPVaFwWe7T/XL+xFD0VrZNEUrozNl48sRXtiwxJU/yDj3J91AgMBAAECggEBALgss8WqQ5uuhNzO+xcrfU0bIHQ+LBkkMJ4zrI1/ye58l0Fy5PLPU5OipSgxYZWchfpcoIN0YdktHH86i80YiIAmm4PxFJlk+rLA79lfS8+S0msdBcFQwlXpiPtKvgosefKBPVE2jG5JuharAB/PUSJFtaoQwK8iEN9gGQbxA3uvmeWWQvxjPuC0/C/Bm2Tm+x5UrvfflqNRXXL3X/QkhU1ZHH/577w3Meua/wPcWVc7kUWhD3pMZDGM//uyYRQezC5oDKMtYAyN/YyiuF4oB3h8wiNtI54/px/caIJWzVk+zg1hqVTByG/MRWYqKIFVhzd58HfUi4vSB/1WR+PLoqECgYEA9PwZGTqqC2Mn9A3gHW882Go+rN/Owc+cOk4Z/C4ho9uh5v2EqaKPMDZkAY1E+FFThQej8ojrVIxoUK9gSQgpa+qOobDsgGrWVSqiP8u0L4M+Xn3Fg5MGquJ0voZ8t6CbdC+u7CV/RgtUnspGm3JgsARO8pOT4LCmwxzbdmDG+ikCgYEA1YH3cOmbd39cVMGE9YGYQF1ujEttkzCKOnfZHbUeOPSnx7FypKOMFaMig9NebsSzzyE2MtIDnm04D8ddnYtIA/y1Lho11rweo9SZ6hfSWU+xENABj9lY54hvQtuWmm9Hqi/BRdRaXncJOX9iQm252I1st+yiE2hM43YmcV2+vG0CgYAWfvfHC04GEarfjE6iJU7PCKKMuViBD5FnATj9oTbRlx982JbQBO9lG/l+8vv8WWtz8cmqQcxqTSJfFlufGTLEiBtk2Zw+BpF77JhNh2UaX9DgWGhEtsGL+5OA01SsgAEGYEKNyLuxMOUqV6S4LX6Xay3ctJSFs3L8w6+bZTOgUQKBgDWlgVnyqKie7MEzGshhNrM9hrBjp3WrZaAJSxmGz8A54QpxEMBDg8hQBDUhYAHvFMr/qlGcqWIeSU7VpjUWsRKnZZLe7RY2kHBT1BSYxbbBKllyGmJdl1Qd2O7wo+fL/DLL6wEzuT0xJbU3x6WvUloSNvYD1DmSJHem0UP87RcFAoGAS3Ucq788OvYge2a06J+SShSBWgG6cuMUwU+NUmsfAqjWQTDSdG63Atrb6jXC/r2gtZuuZSIXukRfKY1pLTrNpOaNfb/S8RWXIR/x6x88GZoMn00u9S+j+c3vzlRfJO2aOiOuClxDta+npCSK4NNna5BuJa/Cr7UewRm4U8D8oWM=";

    @SystemStub private EnvironmentVariables environmentVariables;

    @SystemStub private SystemProperties systemProperties;

    @Mock SSMProvider ssmProvider;

    @Mock SSMProvider ssmProviderWithDecryption;

    private ConfigurationService configurationService;

    @BeforeEach
    void setUp() {
        configurationService = new ConfigurationService(ssmProvider);
        environmentVariables.set("IS_LOCAL", "true");
        environmentVariables.set("AWS_ACCESS_KEY_ID", "ASDFGHJKL");
        environmentVariables.set("AWS_SECRET_ACCESS_KEY", "1234567890987654321");

        systemProperties.set(
                "software.amazon.awssdk.http.service.impl",
                "software.amazon.awssdk.http.urlconnection.UrlConnectionSdkHttpService");
    }

    @Test
    void shouldLoadCertificateFromParameterStore() throws CertificateException {
        environmentVariables.set("DCS_ENCRYPTION_CERT_PARAM", "/dev/dcs/encryption-cert");
        when(ssmProvider.get("/dev/dcs/encryption-cert")).thenReturn(TEST_CERT);

        X509Certificate underTest = (X509Certificate) configurationService.getDcsEncryptionCert();
        assertEquals("C=GB,CN=cri-uk-passport-back", underTest.getIssuerX500Principal().getName());
    }

    @Test
    void shouldLoadPrivateKeyFromParameterStore()
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        environmentVariables.set(
                "PASSPORT_CRI_ENCRYPTION_KEY_PARAM", "/dev/cri/passport/encryption-key");
        when(ssmProvider.withDecryption()).thenReturn(ssmProviderWithDecryption);
        when(ssmProviderWithDecryption.get("/dev/cri/passport/encryption-key"))
                .thenReturn(TEST_PRIVATE_KEY);

        PrivateKey underTest = configurationService.getPassportCriPrivateKey();
        assertEquals("PKCS#8", underTest.getFormat());
        assertEquals("RSA", underTest.getAlgorithm());
    }

    @Test
    void usesLocalSSMProviderWhenRunningLocally(WireMockRuntimeInfo wmRuntimeInfo)
            throws JsonProcessingException {
        stubFor(post("/").willReturn(ok()));

        SSMProvider ssmProvider = new ConfigurationService().getSsmProvider();
        assertThrows(NullPointerException.class, () -> ssmProvider.get("any-old-thing"));

        HashMap requestBody =
                new ObjectMapper()
                        .readValue(
                                getAllServeEvents().get(0).getRequest().getBodyAsString(),
                                HashMap.class);

        assertEquals("any-old-thing", requestBody.get("Name"));
        assertEquals(false, requestBody.get("WithDecryption"));
    }

    @Test
    void shouldCreateThumbprintsFromCertificate()
            throws CertificateException, NoSuchAlgorithmException {
        environmentVariables.set("PASSPORT_CRI_SIGNING_CERT_PARAM", "/dev/dcs/signing-cert");
        when(ssmProvider.get("/dev/dcs/signing-cert")).thenReturn(TEST_CERT);
        Thumbprints underTest = configurationService.makeThumbprints();
        assertEquals("vtBFFZdadqFdSVgScfLruzPoS14", underTest.getSha1Thumbprint());
        assertEquals(
                "7JNbR3kjTHvbDkYt9F_RKwjmYgFaG3dORZqRmnMB-wY", underTest.getSha256Thumbprint());
    }
}
